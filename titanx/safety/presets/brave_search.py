"""Brave Search (web_search + llm_context) egress preset.

Pins both Brave endpoints the IronClaw catalog ships:
``/res/v1/web/search`` for the search tool and ``/res/v1/llm/context``
for the RAG-context tool. Other paths on api.search.brave.com are
denied.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "brave_search"


def build() -> EgressPolicy:
    rules = [
        OutboundRule(
            host_pattern="api.search.brave.com",
            path_prefix="/res/v1/web/search",
            methods=("GET",),
            caller="web_search",
        ),
        OutboundRule(
            host_pattern="api.search.brave.com",
            path_prefix="/res/v1/llm/context",
            methods=("GET",),
            caller="llm_context",
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


from . import register  # noqa: E402
register(NAME, build)
