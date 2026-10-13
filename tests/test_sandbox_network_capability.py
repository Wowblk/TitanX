"""A backend's declared network capability must match its configured network.

The Docker backend defaults to ``network="none"`` (``--network=none`` at
launch) yet historically advertised ``supports_network=True``. The router
trusts that flag to decide whether a ``needs_network`` workload can run, so a
lying declaration turns a "this backend cannot do networking" refusal into a
workload that starts with no egress at all. These tests pin the declaration to
the configuration, at the ``capabilities()`` seam and end-to-end through the
router.
"""

from __future__ import annotations

import pytest

from titanx.sandbox import SandboxRouter, SandboxRouterInput
from titanx.sandbox.backends.docker import (
    DockerSandboxBackend,
    DockerSandboxBackendOptions,
)


def test_docker_declares_no_network_when_disabled():
    caps = DockerSandboxBackend().capabilities()
    assert caps.supports_network is False
    assert "network" not in caps.supported_capabilities


def test_docker_declares_network_when_enabled():
    backend = DockerSandboxBackend(DockerSandboxBackendOptions(network="bridge"))
    caps = backend.capabilities()
    assert caps.supports_network is True
    assert "network" in caps.supported_capabilities


async def test_router_refuses_needs_network_against_networkless_docker():
    # A network-disabled Docker is the only backend; a needs_network request
    # must fail closed with the capability reason, not be routed onto it.
    router = SandboxRouter([DockerSandboxBackend()])

    with pytest.raises(RuntimeError, match="supports_network=False"):
        await router.select(SandboxRouterInput(needs_network=True, min_isolation="docker"))
