"""Compatibility entry; use python run.py for the unified application."""
import sys

from titanx.application import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["Hello, TitanX!"]))
