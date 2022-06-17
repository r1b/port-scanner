# port-scanner

A simple TCP port scanner

## Setup

Ensure that pyenv and pyenv-virtualenv are available on your machine.

- `pyenv virtualenv 3.10.3 port-scanner`
- `pip install -e .`

## Features

- [x] connect() scan 
- [x] Distinguish between open / closed / filtered
- [x] Host discovery with icmplib
- [x] Multiple network specs and multiple port specs
- [x] Display original hostname if resolved
- [ ] Support rDNS
- [x] Randomize port order - still report in requested order
- [x] Parse /etc/services and display corresponding service