"""Compatibility entry; use ``python run.py --web``.

``uvicorn run_gateway:app`` remains supported, but this import-mode object is
built with no storage backend, so ``/api/memory``, ``/api/jobs`` and
``/api/logs`` return 501. Use ``python run.py --web`` (or the ``titanx-app``
console script) for a gateway that opens a local backend under the data dir.
"""
import sys

from titanx.application import create_demo_gateway, main

if __name__ == "__main__":
    raise SystemExit(main(["--web", *sys.argv[1:]]))
else:
    app = create_demo_gateway()
