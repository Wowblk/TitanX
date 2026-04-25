"""Telegram (MTProto via web bridge) egress preset.

The IronClaw catalog wires Telegram through the MTProto-over-web
endpoints under ``*.web.telegram.org``. We mirror that here.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "telegram"


def build() -> EgressPolicy:
    rules = [
        OutboundRule(
            host_pattern="*.web.telegram.org",
            path_prefix="/apiw",
            methods=("GET", "POST"),
            caller="telegram_mtproto",
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


from . import register  # noqa: E402
register(NAME, build)
