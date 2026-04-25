"""Composio egress preset.

Composio fans out to many third-party APIs through its own gateway,
so the only host we need to allowlist is ``backend.composio.dev``.
The actual destination services are gated by Composio's own auth,
not by us.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "composio"


def build() -> EgressPolicy:
    rules = [
        OutboundRule(
            host_pattern="backend.composio.dev",
            path_prefix="/api/v3/",
            methods=("GET", "POST"),
            caller=NAME,
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


from . import register  # noqa: E402
register(NAME, build)
