"""Entry point: `python main.py` launches the password manager CLI."""

from __future__ import annotations

import sys

from password_manager.cli import run


if __name__ == "__main__":
    sys.exit(run())
