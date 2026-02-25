# netcalc

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A command-line tool for network math. It handles IPv4 analysis, subnetting, VLSM allocation, and basic conversions. Built for speed and readable output.

## Features

- **Network Analysis**: Basic breakdown of IPs, masks, host ranges, and network addresses.
- **Subnetting & VLSM**: Split networks into fixed-size subnets or use Variable Length Subnet Masking for optimization.
- **Tools**: Subnet comparison (overlap detection), CIDR/mask conversions, and route command generation (Linux/Cisco).
- **Machine Readable**: Export any command output to JSON or CSV for scripting.

## Installation

```bash
pip install netcalc-tool
```

Or just clone and install locally:

```bash
git clone https://github.com/Yo-omega/net_calculator.git
cd net_calculator
pip install -e .
```

## Quick Examples

```bash
# Direct analysis
netcalc 192.168.1.0/24

# Variable Length Subnet Masking
netcalc vlsm 192.168.1.0/24 50 30 10 5

# Find what subnet fits 100 hosts
netcalc find 100

# Perform bitwise AND between IP and mask
netcalc and 192.168.1.100 255.255.255.0
```

### Output Formats
Use `-f` or `--format` to switch between `table` (default), `json`, or `csv`.

```bash
netcalc -f json 10.0.0.1/8
```

## Options

- `-f, --format [table|json|csv]`: Output format.
- `--no-color`: Disable colors (useful for logging/CI).
- `--version`: Show version.

## Development

```bash
# Setup venv
python -m venv .venv
source .venv/bin/activate

# Install dev deps (pytest, coverage)
pip install -e ".[dev]"

# Run tests
pytest
```

## License

MIT — see [LICENSE](LICENSE).

---

[Yo-omega](https://github.com/Yo-omega)