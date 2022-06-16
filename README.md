# port-scanner

A simple TCP port scanner

## Setup

Ensure that pyenv and pyenv-virtualenv are available on your machine.

- `pyenv virtualenv 3.10.3 port-scanner`
- `pip install -e .`

## Features

- [x] Implement connect() scan for cidr + range of ports
- [x] Distinguish between open / closed / filtered
- [x] Host discovery with icmplib
- [ ] Multiple host / network specs and multiple port specs
  - Overlapping ranges are interesting - nmap by default will scan an address each time it is seen (see --unique)
  - Not sure how this works for ports
- [ ] Support rDNS
- [ ] Randomize host / port order - still report in requested order
- [x] Parse /etc/services and display corresponding service
- [ ] Scan delay / max concurrent host connections / other rate limiting
    - This is the hardest thing to get right
    - Nmap has an instructive implementation https://github.com/nmap/nmap/blob/df33da47228e3f32f9a332f7db0a0a4f2f14084d/scan_engine.cc#L2779-L2807