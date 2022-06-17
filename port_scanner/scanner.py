from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

import typer

from port_scanner.parser import parse_targets
from port_scanner.target import Target, TargetPort

MAX_WORKERS = 32


def run_rdns_probes(executor: ThreadPoolExecutor, targets: List[Target]):
    dns_probe_futures = {}

    for target in targets:
        if not target.hostname:
            dns_probe_futures[executor.submit(target.dns_probe)] = target

    for future in as_completed(dns_probe_futures):
        _ = future.result()


def run_ping_probes(executor: ThreadPoolExecutor, targets: List[Target]):
    ping_probe_futures = {}

    for target in targets:
        ping_probe_futures[executor.submit(target.ping_probe)] = target

    for future in as_completed(ping_probe_futures):
        _ = future.result()
        target = ping_probe_futures[future]
        if target.status == Target.Status.UP:
            typer.echo(f"Host {target.host} is up")


def run_connect_scan(executor: ThreadPoolExecutor, targets: List[Target]):
    connect_probe_futures = {}
    for target in targets:
        if target.status == Target.Status.DOWN:
            continue
        for target_port in target.shuffled_ports:
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


def scan(network_specs: List[str], port_spec: str):
    targets = parse_targets(network_specs, port_spec)

    # TODO: Restructure the main loop to support rate limiting and other flow control features.
    # Ref: https://github.com/nmap/nmap/blob/df33da47228e3f32f9a332f7db0a0a4f2f14084d/scan_engine.cc#L2779-L2807
    # TODO(perf): Use select / epoll
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        run_rdns_probes(executor, targets)
        run_ping_probes(executor, targets)
        run_connect_scan(executor, targets)

    # Report results in user-specified order
    for target in targets:
        typer.echo(target.report())
