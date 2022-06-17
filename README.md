# port-scanner

A simple TCP port scanner.

## Setup

Ensure that pyenv and pyenv-virtualenv are available on your machine.

- `pyenv virtualenv 3.10.3 port-scanner`
- `pip install -e .`

## Usage

 - `port-scanner scanme.nmap.org`
 - See `port-scanner --help` for full documentation

## Tests

Run the tests with `pytest -vsx`