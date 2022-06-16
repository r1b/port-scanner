import logging
import socket
from concurrent.futures import as_completed, ThreadPoolExecutor
from enum import Enum
from ipaddress import ip_network
from typing import Iterable, List

import typer
from icmplib import ping

CONNECT_TIMEOUT_SECONDS = 2
MIN_PORT = 1
MAX_PORT = 65535
MAX_WORKERS = 32

cli = typer.Typer()

logging.basicConfig()
logger = logging.getLogger("port-scanner")


def parse_ports(ports: List[str]) -> Iterable[int]:
    if ports is None:
        return range(MIN_PORT, MAX_PORT + 1)

    if "-" not in ports:
        ports = [ports, ports]
    else:
        ports = ports.split("-")

    ports = [int(port) for port in ports]
    min_port, max_port = ports

    for port in min_port, max_port:
        if port not in range(MIN_PORT, MAX_PORT + 1):
            raise ValueError(f"Invalid port: {port}")

    if min_port > max_port:
        raise ValueError(f"Invalid range: {min_port}-{max_port}")

    return range(min_port, max_port + 1)


def parse_hostname(hostname):
    addrinfos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    # Don't prefer IPv4 or IPv6 - just take the first result
    sockinfo = addrinfos[0][-1]
    address = sockinfo[0]
    return ip_network(address)


def parse_network(network):
    try:
        return ip_network(network)
    except ValueError:
        return parse_hostname(network)


class Target:
    class Status(Enum):
        DOWN = "down"
        UP = "up"

    def __init__(self, host: str, ports: Iterable[int]):
        self.host = host
        self.ports = [TargetPort(host, port) for port in ports]
        self.status = None

    def probe(self):
        self.status = self._probe()
        logger.debug("target probe complete: host=%s status=%s", self.host, self.status)

    def _probe(self) -> Status:
        result = ping(self.host, count=1, privileged=False)
        return Target.Status.UP if result.is_alive else Target.Status.DOWN

    def report(self) -> str:
        lines = [f"Host report for {self.host}:", f"Host is {self.status.value}"]

        notable_ports = [
            target_port for target_port in self.ports
            if target_port.status == TargetPort.Status.OPEN
        ] if self.status == Target.Status.UP else []

        if not notable_ports:
            lines.append("All ports filtered")
        else:
            lines.append("\t".join(("port", "service", "status")))
            for target_port in notable_ports:
                port = f"tcp/{target_port.port}"
                try:
                    service = socket.getservbyport(target_port.port, "tcp")
                except OSError:
                    service = "unknown"
                status = target_port.status
                lines.append("\t".join((port, service, status.value)))
            lines.append("All other ports filtered or closed")

        return "\n".join(lines)


class TargetPort:
    class Status(Enum):
        CLOSED = "closed"
        FILTERED = "filtered"
        OPEN = "open"

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.status = None

    def probe(self):
        self.status = self._probe()
        logger.debug("target port probe complete: host=%s port=%d status=%s", self.host, self.port, self.status)

    def _probe(self) -> Status:
        # Nmap has much more sophisticated logic here
        # Ref: https://github.com/nmap/nmap/blob/df33da47228e3f32f9a332f7db0a0a4f2f14084d/scan_engine_connect.cc#L190-L267
        try:
            conn = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT_SECONDS)
        except ConnectionRefusedError:
            return TargetPort.Status.CLOSED
        except TimeoutError:
            return TargetPort.Status.FILTERED

        try:
            conn.close()
        finally:
            return TargetPort.Status.OPEN


@cli.command()
def main(network: str, debug: bool = typer.Option(False, "--debug"), ports: str = None):
    if debug:
        logger.setLevel(logging.DEBUG)

    network = parse_network(network)
    ports = parse_ports(ports)

    targets = {}
    for host in network.hosts():
        host = str(host)
        targets[host] = Target(host, ports)

    # TODO: Restructure the main loop to support rate limiting and other flow control features.
    # Ref: https://github.com/nmap/nmap/blob/df33da47228e3f32f9a332f7db0a0a4f2f14084d/scan_engine.cc#L2779-L2807
    # TODO(perf): Use select / epoll
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        # Host discovery
        host_probe_futures = {}

        for target in targets.values():
            host_probe_futures[executor.submit(target.probe)] = target

        for future in as_completed(host_probe_futures):
            target = host_probe_futures[future]
            if target.status == Target.Status.UP:
                typer.echo(f"Host {target.host} is up")

        # Port scan
        port_probe_futures = {}
        for target in targets.values():
            if target.status == Target.Status.DOWN:
                continue
            for target_port in target.ports:
                port_probe_futures[executor.submit(target_port.probe)] = target_port

        for future in as_completed(port_probe_futures):
            target_port = port_probe_futures[future]
            if target_port.status == TargetPort.Status.OPEN:
                typer.echo(f"Discovered open port tcp/{target_port.port} on {target_port.host}")

    # Report results in user-specified order
    for host in network.hosts():
        host = str(host)
        target = targets[host]
        typer.echo(target.report())
