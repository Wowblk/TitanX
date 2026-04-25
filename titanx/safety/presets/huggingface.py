"""Hugging Face egress preset.

Common destination for model + dataset downloads. Three hosts cover
the realistic surface: the API, the CDN that serves blobs, and the
Inference API. ``caller="huggingface"`` is the convention; pass it
to ``EgressGuard.enforce(..., caller="huggingface")`` from the host
HTTP client wrapping ``huggingface_hub`` calls.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "huggingface"


def build() -> EgressPolicy:
    rules = [
        OutboundRule(
            host_pattern="huggingface.co",
            path_prefix="/",
            methods=("GET", "POST", "PUT", "DELETE"),
            caller=NAME,
        ),
        OutboundRule(
            host_pattern="cdn-lfs.huggingface.co",
            path_prefix="/",
            methods=("GET",),
            caller=NAME,
        ),
        OutboundRule(
            host_pattern="api-inference.huggingface.co",
            path_prefix="/",
            methods=("POST",),
            caller=NAME,
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


from . import register  # noqa: E402
register(NAME, build)
