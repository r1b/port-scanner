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
    debug: bool = typer.Option(False, "-d"),  # noqa B008
    ports: str = typer.Option(None, "-p"),  # noqa B008
):
    if debug:
        logger.setLevel(logging.DEBUG)

    scan(networks, ports)
