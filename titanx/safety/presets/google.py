"""Google Workspace egress preset.

Covers the IronClaw specs that target ``googleapis.com``: Gmail,
Calendar, Drive, Docs, Sheets, Slides. Each rule pins the path-prefix
the corresponding spec declares so a Drive token cannot accidentally
post to Gmail's send endpoint.

Caller pinning is intentionally per-tool: ``caller="gmail"``,
``caller="google_drive"`` etc. Code that doesn't carry an identity
will not match these rules — generic fallthroughs must be added
separately if desired.
"""
from __future__ import annotations

from ..egress import EgressPolicy, OutboundRule

NAME = "google"


def build() -> EgressPolicy:
    rules = [
        # Gmail — gmail.googleapis.com /gmail/v1/.
        OutboundRule(
            host_pattern="gmail.googleapis.com",
            path_prefix="/gmail/v1/",
            methods=("GET", "POST", "DELETE"),
            caller="gmail",
        ),
        # Calendar — www.googleapis.com /calendar/v3/.
        OutboundRule(
            host_pattern="www.googleapis.com",
            path_prefix="/calendar/v3/",
            methods=("GET", "POST", "PUT", "DELETE"),
            caller="google_calendar",
        ),
        # Drive (metadata + media), pinned to the Drive v3 endpoints.
        OutboundRule(
            host_pattern="www.googleapis.com",
            path_prefix="/drive/v3/",
            methods=("GET", "POST", "PATCH", "DELETE"),
            caller="google_drive",
        ),
        OutboundRule(
            host_pattern="www.googleapis.com",
            path_prefix="/upload/drive/v3/",
            methods=("POST", "PATCH"),
            caller="google_drive",
        ),
        # Docs.
        OutboundRule(
            host_pattern="docs.googleapis.com",
            path_prefix="/v1/documents",
            methods=("GET", "POST"),
            caller="google_docs",
        ),
        # Sheets.
        OutboundRule(
            host_pattern="sheets.googleapis.com",
            path_prefix="/v4/spreadsheets",
            methods=("GET", "POST", "PUT"),
            caller="google_sheets",
        ),
        # Slides.
        OutboundRule(
            host_pattern="slides.googleapis.com",
            path_prefix="/v1/presentations",
            methods=("GET", "POST"),
            caller="google_slides",
        ),
        # OAuth 2 token endpoint — every Google client refreshes here.
        # POST-only and pinned to /token to keep the surface small.
        OutboundRule(
            host_pattern="oauth2.googleapis.com",
            path_prefix="/token",
            methods=("POST",),
            caller=None,  # any Google tool may need to refresh
        ),
    ]
    return EgressPolicy(rules=rules, default_action="deny")


from . import register  # noqa: E402
register(NAME, build)
