"""Discord egress preset.

There is no IronClaw spec for Discord today; this preset gives the
common shape (REST API + CDN) so a host that wires up its own Discord
tool can opt in by name. ``caller="discord"`` is a convention; pass
the same value to ``EgressGuard.enforce(..., caller="discord")``.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "discord"


def build() -> EgressPolicy:
    rules = [
        OutboundRule(
            host_pattern="discord.com",
            path_prefix="/api/",
            methods=("GET", "POST", "PUT", "PATCH", "DELETE"),
            caller=NAME,
        ),
        # CDN — message attachments, avatars, etc. GET only; nothing in
        # a Discord bot use-case writes here.
        OutboundRule(
            host_pattern="cdn.discordapp.com",
            path_prefix="/",
            methods=("GET",),
            caller=NAME,
        ),
        # Media proxy for embedded images / link previews.
        OutboundRule(
            host_pattern="media.discordapp.net",
            path_prefix="/",
            methods=("GET",),
            caller=NAME,
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


from . import register  # noqa: E402
register(NAME, build)
