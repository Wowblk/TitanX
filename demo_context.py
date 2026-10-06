"""Compatibility entry; use python run.py --check-context."""
import sys

from titanx.application import main

if __name__ == "__main__":
    raise SystemExit(main(["--check-context", *sys.argv[1:]]))
