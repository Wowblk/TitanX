"""Bundled egress allowlist presets.

Why presets exist
-----------------

Hand-rolling an ``EgressPolicy`` for each integration target — every
GitHub host, Slack endpoint, Hugging Face mirror, etc. — is the kind
of work that produces subtle drift across deployments. NemoClaw ships
the same idea as YAML preset files under ``policies/presets/`` and
treats them as opt-in, default-off knobs. The TitanX equivalent is
this package: each module is a small builder that yields a list of
``OutboundRule`` instances scoped to a specific destination, plus a
canonical ``caller`` string.

Usage
-----

.. code:: python

    from titanx.safety import EgressGuard, EgressPolicy
    from titanx.safety.presets import compose, get

    policy = compose(["github", "slack"])  # default-deny + 2 allowlists
    guard = EgressGuard(policy)

    # …or grab a single preset and stitch it into an existing policy:
    rules = get("brave_search").rules
    my_policy.rules.extend(rules)

Each preset's ``caller`` matches the IronClaw spec name where one
exists (so passing ``caller="github"`` to ``guard.enforce`` will hit
the github preset). Calls without a caller still match generic rules
in the policy, but **never** match a preset rule — the caller pin is
fail-closed by design.

Adding a preset
---------------

Drop a new module here, expose ``NAME: str`` and ``def build() ->
EgressPolicy``, and register it in ``_REGISTRY``. Keep each preset to
the minimum surface a real integration needs; default-deny is the
floor and presets only add allow rules.
"""

from __future__ import annotations

from typing import Callable

from ..egress import EgressPolicy, OutboundRule

PresetBuilder = Callable[[], EgressPolicy]


def _merge(*policies: EgressPolicy) -> EgressPolicy:
    """Merge multiple presets into a single default-deny policy.

    The resulting policy preserves rule order (first-match wins inside
    ``EgressGuard.check``) and forces ``default_action="deny"`` no
    matter what the inputs say. Allowing a preset to flip the default
    would let one careless import open up the whole guard.
    """
    rules: list[OutboundRule] = []
    for p in policies:
        rules.extend(p.rules)
    return EgressPolicy(rules=rules, default_action="deny")


# The registry maps preset name → builder. Each module re-exports its
# builder under ``build`` so the registry stays trivially auditable.
_REGISTRY: dict[str, PresetBuilder] = {}


def register(name: str, builder: PresetBuilder) -> None:
    """Add a preset to the registry.

    Useful for application-defined presets that live outside this
    package; the bundled presets register themselves below.
    """
    if not name or not isinstance(name, str):
        raise ValueError(f"preset name must be a non-empty str: {name!r}")
    if name in _REGISTRY:
        raise ValueError(f"preset {name!r} is already registered")
    _REGISTRY[name] = builder


def get(name: str) -> EgressPolicy:
    """Return a fresh ``EgressPolicy`` for one preset.

    Raises ``KeyError`` for unknown presets so a typo at deployment
    time fails loudly rather than silently leaving the guard
    rule-less.
    """
    if name not in _REGISTRY:
        raise KeyError(
            f"unknown egress preset {name!r}; "
            f"available: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]()


def compose(names: list[str]) -> EgressPolicy:
    """Build a default-deny policy from a list of preset names."""
    return _merge(*(get(n) for n in names))


def available() -> list[str]:
    """Sorted list of registered preset names."""
    return sorted(_REGISTRY)


# Bundled presets self-register on import. We keep the imports at the
# bottom of the module so ``register`` is defined before any preset
# tries to call it.
from . import (  # noqa: E402, F401
    brave_search,
    composio,
    discord,
    github,
    google,
    huggingface,
    npm_registry,
    pypi,
    slack,
    telegram,
)


__all__ = [
    "PresetBuilder",
    "available",
    "compose",
    "get",
    "register",
]
