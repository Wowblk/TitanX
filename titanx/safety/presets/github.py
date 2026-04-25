"""GitHub egress preset.

Mirrors ``policies/presets/github.yaml`` from NemoClaw: only the API
host and the upload host, and only the methods the catalog spec
declares. ``caller="github"`` matches the IronClaw WASM spec name
``IRONCLAW_WASM_TOOLS["github"]``.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "github"


def build() -> EgressPolicy:
    rules = [
        OutboundRule(
            host_pattern="api.github.com",
            path_prefix="/",
            methods=("GET", "POST", "PUT", "DELETE", "PATCH"),
            caller=NAME,
        ),
        # ``uploads.github.com`` is used by release-asset uploads. The
        # IronClaw spec doesn't separate it but real workloads need it.
        OutboundRule(
            host_pattern="uploads.github.com",
            path_prefix="/",
            methods=("POST",),
            caller=NAME,
        ),
        # Raw content is fetched via ``raw.githubusercontent.com``;
        # GET-only because the workload should never write back here.
        OutboundRule(
            host_pattern="raw.githubusercontent.com",
            path_prefix="/",
            methods=("GET",),
            caller=NAME,
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


# Self-registration is performed in ``__init__.py`` to keep this module
# importable in isolation (tests / inspection).
from . import register  # noqa: E402
register(NAME, build)
