import logging
from typing import List

import typer

from port_scanner.scanner import scan

cli = typer.Typer()

logging.basicConfig()
logger = logging.getLogger("port-scanner")


@cli.command()
def main(
    networks: List[str],
    debug: bool = typer.Option(False, "-d", help="Enable debug logs"),
    ports: str = typer.Option(
        None, "-p", help="Ports to scan, e.g: 1,23,80-81"
    ),
):
    """
    Scan NETWORKS on the specified ports. Performs the following checks in order:

    \b
    * rDNS scan to determine target hostnames
    * ICMP ping scan to determine if the target is up
    * TCP connect scan on those targets that were determined to be up

    \b
    Examples:
        port-scanner scanme.nmap.org                    # Scans common ports
        port-scanner scanme.nmap.org -p 22,80           # Scans specific ports
        port-scanner scanme.nmap.org -p 8000-9000       # Scans a range of ports
        port-scanner scanme.nmap.org -p-                # Scans all TCP ports
        port-scanner scanme.nmap.org 192.168.1.0/24     # Scan multiple networks
    """
    if debug:
        logger.setLevel(logging.DEBUG)

    scan(networks, ports)
