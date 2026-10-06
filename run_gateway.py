"""Compatibility entry; use python run.py --web.

uvicorn run_gateway:app remains supported; storage opens during lifespan.
"""
import sys

from titanx.application import create_demo_gateway, main

if __name__ == "__main__":
    raise SystemExit(main(["--web", *sys.argv[1:]]))
else:
    app = create_demo_gateway()
