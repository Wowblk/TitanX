"""Default wiring must let operators configure what the backends launch.

``_default_backends`` built ``DockerSandboxBackend()`` and
``MicrosandboxSandboxBackend()`` with no options, so two capabilities were
unreachable through ``create_sandboxed_runtime``:

* Docker always ran ``--network=none`` — there was no way to satisfy a
  ``needs_network`` workload;
* the microVM backend always had ``image=""``, and ``is_available`` fails
  closed without an image, so ``run_browser_task`` (strong isolation) could
  never route in the default wiring at all.

These tests drive the factory and then ask the router it built what the
backends declare, so they pin the wiring rather than the option storage.
"""
from __future__ import annotations

import sys
import types

from titanx.factory import CreateSandboxedRuntimeOptions, create_sandboxed_runtime
from titanx.safety import SafetyLayer
from titanx.sandbox.types import SandboxRouterInput
from titanx.types import LlmAdapter, LlmTurnResult


class _NullLlm(LlmAdapter):
    async def respond(self, config, state) -> LlmTurnResult:
        return LlmTurnResult(type="text", text="(done)")


def _runtime(**kwargs):
    return create_sandboxed_runtime(
        CreateSandboxedRuntimeOptions(llm=_NullLlm(), safety=SafetyLayer(), **kwargs)
    )


def _backends(runtime):
    return {backend.kind: backend for backend in runtime._tools._router.list_backends()}


def _install_fake_sdk(monkeypatch) -> None:
    # Availability only needs the package to import; routing never boots a VM.
    monkeypatch.setitem(sys.modules, "microsandbox", types.ModuleType("microsandbox"))
    monkeypatch.setattr(
        "titanx.sandbox.backends.microsandbox._host_supports_microvm",
        lambda: True,
    )


async def test_factory_defaults_leave_network_off_everywhere():
    backends = _backends(_runtime())

    assert backends["docker"].capabilities().supports_network is False
    assert backends["microsandbox"].capabilities().supports_network is False
    # No image configured: the strong-isolation tier must stay unavailable.
    assert await backends["microsandbox"].is_available() is False


async def test_factory_can_enable_docker_network():
    backends = _backends(_runtime(docker_network="bridge"))

    assert backends["docker"].capabilities().supports_network is True


async def test_factory_can_configure_microsandbox_image_and_network(monkeypatch):
    _install_fake_sdk(monkeypatch)
    runtime = _runtime(microsandbox_image="python", microsandbox_network_enabled=True)
    backend = _backends(runtime)["microsandbox"]

    assert await backend.is_available() is True
    assert backend.capabilities().supports_network is True

    # End to end through the router the factory built: a strong-isolation
    # request must now land on the microVM tier instead of failing closed.
    selection = await runtime._tools._router.select(
        SandboxRouterInput(min_isolation="microsandbox", requires_strong_isolation=True)
    )
    assert selection.backend.kind == "microsandbox"
