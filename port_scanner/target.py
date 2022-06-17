import logging
import random
import socket
from enum import Enum
from functools import cached_property
from typing import Iterable, Optional

from icmplib import ping

COL_PADDING = 2
CONNECT_TIMEOUT_SECONDS = 2

logger = logging.getLogger("port-scanner")


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

    @cached_property
    def shuffled_ports(self):
        shuffled_ports = self.ports[:]
        random.shuffle(shuffled_ports)
        return shuffled_ports

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
