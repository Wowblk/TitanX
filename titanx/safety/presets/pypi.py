"""PyPI egress preset.

For tools that resolve and download Python packages. Read-only
(GET) on both the metadata and file hosts. No upload host —
publishing is not a sandbox use-case; if you need it, add a custom
rule for ``upload.pypi.org``.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "pypi"


def build() -> EgressPolicy:
    rules = [
        OutboundRule(
            host_pattern="pypi.org",
            path_prefix="/",
            methods=("GET",),
            caller=NAME,
        ),
        OutboundRule(
            host_pattern="files.pythonhosted.org",
            path_prefix="/",
            methods=("GET",),
            caller=NAME,
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


from . import register  # noqa: E402
register(NAME, build)
