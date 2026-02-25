# How to contribute

Thanks for checking out the project! If you want to help make `netcalc` better, here's a rough guide on how to get started.

## Setup

1. Fork the repo.
2. Clone it and set up a venv:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```
3. Run `pytest` to make sure everything is good.

## Making changes

- **Small stuff**: Just open a PR.
- **Big stuff**: Maybe open an issue first to talk about it.
- **Style**: We use type hints and dataclasses for pretty much everything. Keep logic in `core.py` and rendering in `display.py`.
- **Tests**: If you add a feature, please add a test for it in `tests/test_core.py`.

## Repo layout

- `src/netcalc/core.py`: All the network math.
- `src/netcalc/display.py`: Making things look nice in the terminal (using `rich`).
- `src/netcalc/cli.py`: The command line interface (using `click`).
- `tests/`: Where we keep the test suite.

Happy hacking!
