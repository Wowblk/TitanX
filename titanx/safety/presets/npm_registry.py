"""npm registry egress preset.

GET-only allowlist for tools that resolve / download npm packages.
The standard registry plus the tarball CDN hosts. Like ``pypi``, we
intentionally exclude any publish endpoints.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "npm_registry"


def build() -> EgressPolicy:
    rules = [
        OutboundRule(
            host_pattern="registry.npmjs.org",
            path_prefix="/",
            methods=("GET",),
            caller=NAME,
        ),
        # Tarballs sit on a sibling host.
        OutboundRule(
            host_pattern="registry.npmmirror.com",
            path_prefix="/",
            methods=("GET",),
            caller=NAME,
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


from . import register  # noqa: E402
register(NAME, build)
