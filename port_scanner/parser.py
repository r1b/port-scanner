import json
import socket
from ipaddress import ip_network
from pathlib import Path
from typing import Iterable, List, Optional

from port_scanner.target import Target

MIN_PORT = 1
MAX_PORT = 65535


def load_most_common_ports():
    with (
        Path(__file__).parent / "assets" / "most_common_ports.json"
    ).open() as most_common_ports:
        # Ref: https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/
        return json.load(most_common_ports)


def parse_targets(network_specs: List[str], port_spec: str) -> List[Target]:
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


def parse_ports(port_specs: Optional[str]) -> Iterable[int]:
    # TODO: Break this up
    if port_specs is None:
        return load_most_common_ports()

    target_ports = [False for _ in range(MAX_PORT + 1)]

    for port_spec in port_specs.split(","):
        if port_spec == "-":
            target_ports = [True for _ in range(MAX_PORT + 1)]
            break

        if "-" in port_spec:
            lhs, rhs = port_spec.split("-")
            port_spec = [lhs or str(MIN_PORT), rhs or str(MAX_PORT)]
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
