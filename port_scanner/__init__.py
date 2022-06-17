import logging
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from ipaddress import ip_network
from typing import Iterable, List, Optional

import typer
from icmplib import ping

COL_PADDING = 2
CONNECT_TIMEOUT_SECONDS = 2
MIN_PORT = 1
MAX_PORT = 65535
MAX_WORKERS = 32

cli = typer.Typer()

logging.basicConfig()
logger = logging.getLogger("port-scanner")


def parse_ports(port_specs: str) -> Iterable[int]:
    target_ports = [False for _ in range(MAX_PORT + 1)]

    for port_spec in port_specs.split(","):
        if port_spec == "-":
            target_ports = [True for _ in range(MAX_PORT + 1)]
            break

        if "-" in port_spec:
            port_spec = port_spec.split("-")
        else:
            port_spec = [port_spec, port_spec]

        port_spec = [int(port) for port in port_spec]
        min_port, max_port = port_spec

        for port in min_port, max_port:
            if port not in range(MIN_PORT, MAX_PORT + 1):
                raise ValueError(f"Invalid port: {port}")

        if min_port > max_port:
            raise ValueError(f"Invalid range: {min_port}-{max_port}")

        for i in range(min_port, max_port + 1):
            target_ports[i] = True

    # port 0 is never allowed
    return [i for i in range(1, MAX_PORT + 1) if target_ports[i]]


def parse_hostname(hostname: str) -> str:
    addrinfos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    # Don't prefer IPv4 or IPv6 - just take the first result
    sockinfo = addrinfos[0][-1]
    address = sockinfo[0]
    return address


def parse_targets(network_specs: List[str], port_spec: str) -> List["Target"]:
    targets = []
    ports = parse_ports(port_spec)

    for network_spec in network_specs:
        try:
            network = ip_network(network_spec)
            is_hostname = False
        except ValueError:
            network = ip_network(parse_hostname(network_spec))
            is_hostname = True

        hostname = network_spec if is_hostname else None

        targets += [
            Target(str(host), ports, hostname=hostname)
            for host in network.hosts()
        ]

    return targets


class Target:
    class Status(Enum):
        DOWN = "down"
        UP = "up"

    def __init__(
        self, host: str, ports: Iterable[int], hostname: Optional[str] = None
    ):
        self.host = host
        self.ports = [TargetPort(host, port) for port in ports]
        self.hostname = hostname
        self.status = None

        random.shuffle(self.ports)

    @property
    def notable_ports(self):
        # TODO: nmap does something smart where a closed or filtered port
        # is considered notable if its status is a minority
        if self.status == Target.Status.DOWN:
            return []

        return [
            target_port
            for target_port in self.ports
            if target_port.status == TargetPort.Status.OPEN
        ]

    def dns_probe(self):
        self.hostname = self._dns_probe()
        logger.debug(
            "rdns probe complete: host=%s hostname=%s",
            self.host,
            self.hostname,
        )

    def _dns_probe(self) -> Optional[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(self.host)
        except OSError:
            hostname = None

        return hostname

    def ping_probe(self):
        self.status = self._ping_probe()
        logger.debug(
            "target ping probe complete: host=%s status=%s",
            self.host,
            self.status,
        )

    def _ping_probe(self) -> Status:
        result = ping(self.host, count=1, privileged=False)
        return Target.Status.UP if result.is_alive else Target.Status.DOWN

    def report(self) -> str:
        hostname = f" ({self.hostname})" if self.hostname else ""
        lines = [
            f"Host report for {self.host}{hostname}",
            f"Host is {self.status.value}",
        ]

        if not self.notable_ports:
            lines.append("All ports filtered or closed")
        else:
            table_lines = [("port", "service", "status")]
            for target_port in self.notable_ports:
                table_lines.append(target_port.report())
            col_width = (
                max(len(word) for line in table_lines for word in line)
                + COL_PADDING
            )
            for line in table_lines:
                lines.append("".join(word.ljust(col_width) for word in line))
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

    def connect_probe(self):
        self.status = self._connect_probe()
        logger.debug(
            "target port connect probe complete: host=%s port=%d status=%s",
            self.host,
            self.port,
            self.status,
        )

    def _connect_probe(self) -> Status:
        # Nmap has much more sophisticated logic here
        # Ref: https://github.com/nmap/nmap/blob/df33da47228e3f32f9a332f7db0a0a4f2f14084d/scan_engine_connect.cc#L190-L267
        try:
            conn = socket.create_connection(
                (self.host, self.port), timeout=CONNECT_TIMEOUT_SECONDS
            )
        except ConnectionRefusedError:
            return TargetPort.Status.CLOSED
        except TimeoutError:
            return TargetPort.Status.FILTERED

        try:
            conn.close()
        finally:
            pass

        return TargetPort.Status.OPEN

    def report(self) -> Iterable[str]:
        port = f"tcp/{self.port}"
        try:
            service = socket.getservbyport(self.port, "tcp")
        except OSError:
            service = "unknown"
        return port, service, self.status.value


@cli.command()
def main(
    networks: List[str],
    debug: bool = typer.Option(False, "-d"),  # noqa B008
    ports: str = typer.Option(..., "-p"),  # noqa B008
):
    if debug:
        logger.setLevel(logging.DEBUG)

    targets = parse_targets(networks, ports)

    # TODO: Restructure the main loop to support rate limiting and other flow control features.
    # Ref: https://github.com/nmap/nmap/blob/df33da47228e3f32f9a332f7db0a0a4f2f14084d/scan_engine.cc#L2779-L2807
    # TODO(perf): Use select / epoll
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        # rDNS
        dns_probe_futures = {}

        for target in targets:
            if not target.hostname:
                dns_probe_futures[executor.submit(target.dns_probe)] = target

        for future in as_completed(dns_probe_futures):
            _ = future.result()

        # Host discovery
        ping_probe_futures = {}

        for target in targets:
            ping_probe_futures[executor.submit(target.ping_probe)] = target

        for future in as_completed(ping_probe_futures):
            _ = future.result()
            target = ping_probe_futures[future]
            if target.status == Target.Status.UP:
                typer.echo(f"Host {target.host} is up")

        # Port scan
        connect_probe_futures = {}
        for target in targets:
            if target.status == Target.Status.DOWN:
                continue
            for target_port in target.ports:
                connect_probe_futures[
                    executor.submit(target_port.connect_probe)
                ] = target_port

        for future in as_completed(connect_probe_futures):
            _ = future.result()
            target_port = connect_probe_futures[future]
            if target_port.status == TargetPort.Status.OPEN:
                typer.echo(
                    f"Discovered open port tcp/{target_port.port} on {target_port.host}"
                )

    # Report results in user-specified order
    for target in targets:
        typer.echo(target.report())
