"""Slack egress preset.

The IronClaw catalog declares ``slack.com/api/`` for the Web API. We
also include ``files.slack.com`` because file uploads/downloads use
that host. ``hooks.slack.com`` is the incoming-webhook endpoint —
included for parity with NemoClaw's preset.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "slack"


def build() -> EgressPolicy:
    rules = [
        OutboundRule(
            host_pattern="slack.com",
            path_prefix="/api/",
            methods=("GET", "POST"),
            caller=NAME,
        ),
        OutboundRule(
            host_pattern="files.slack.com",
            path_prefix="/",
            methods=("GET", "POST"),
            caller=NAME,
        ),
        OutboundRule(
            host_pattern="hooks.slack.com",
            path_prefix="/services/",
            methods=("POST",),
            caller=NAME,
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


from . import register  # noqa: E402
register(NAME, build)
