"""Docker sandbox image-digest pin enforcement.

Mirrors NemoClaw's blueprint-level digest lockstep: ``DockerSandboxBackend``
refuses to launch the container if the resolved image digest does not
match the pin (either ``options.expected_image_digest`` or the
per-call ``request.image_digest`` plumbed from ``AgentPolicy``).

Tests are hermetic — the digest resolver and the docker subprocess are
both stubbed so no real container ever runs.
"""

from __future__ import annotations

import pytest

from titanx.policy.types import AgentPolicy
from titanx.policy.validation import PolicyValidationError, validate_policy
from titanx.sandbox.backends.docker import (
    DockerSandboxBackend,
    DockerSandboxBackendOptions,
    ImageDigestMismatch,
)
from titanx.sandbox.types import SandboxExecutionRequest


PIN = "sha256:" + ("a" * 64)
OTHER = "sha256:" + ("b" * 64)


def _backend(*, image: str, expected: str | None = None,
             resolved: str | None = None) -> DockerSandboxBackend:
    """Build a backend whose subprocess stub returns a fixed result.

    The digest resolver is replaced with a coroutine that returns the
    canned ``resolved`` value, so tests don't need ``docker inspect``
    on the host.
    """
    async def _resolver(_bin: str, _img: str) -> str | None:
        return resolved

    async def _exec_stub(req, session):
        # Surface the request so the test can assert on it.
        return {"exit_code": 0, "stdout": "ok", "stderr": ""}

    opts = DockerSandboxBackendOptions(
        image=image,
        expected_image_digest=expected,
        digest_resolver=_resolver,
        executor=_exec_stub,
    )
    return DockerSandboxBackend(opts)


class TestPolicyValidation:
    def test_image_digest_must_look_like_oci(self):
        with pytest.raises(PolicyValidationError, match="image_digest"):
            validate_policy(AgentPolicy(image_digest="not-a-digest"))

    def test_image_digest_short_hex_rejected(self):
        with pytest.raises(PolicyValidationError, match="image_digest"):
            validate_policy(AgentPolicy(image_digest="sha256:deadbeef"))

    def test_image_digest_none_is_allowed(self):
        # No pin means "no check"; validation must accept this.
        validate_policy(AgentPolicy(image_digest=None))

    def test_image_digest_canonical_form_accepted(self):
        validate_policy(AgentPolicy(image_digest=PIN))


class TestExecuteRefusesOnMismatch:
    @pytest.mark.asyncio
    async def test_options_pin_mismatch_returns_error_result(self):
        backend = _backend(
            image="alpine:latest",
            expected=PIN,
            resolved=OTHER,
        )
        result = await backend.execute(SandboxExecutionRequest(command="true"))
        # The broad except in execute turns ImageDigestMismatch into an
        # error result so the LLM sees a deterministic failure rather
        # than a runtime exception. Either ``digest mismatch`` or the
        # OTHER digest must appear in stderr.
        assert result.exit_code != 0
        assert "digest" in result.stderr.lower()
        assert OTHER in result.stderr or PIN in result.stderr

    @pytest.mark.asyncio
    async def test_options_pin_match_proceeds(self):
        backend = _backend(
            image="alpine:latest",
            expected=PIN,
            resolved=PIN,
        )
        result = await backend.execute(SandboxExecutionRequest(command="true"))
        assert result.exit_code == 0
        assert result.stdout == "ok"

    @pytest.mark.asyncio
    async def test_request_pin_overrides_options(self):
        # Per-call pin (from AgentPolicy.image_digest plumbed by the
        # tool runtime) takes precedence over the deployment default.
        backend = _backend(
            image="alpine:latest",
            expected=OTHER,    # would have allowed OTHER
            resolved=OTHER,
        )
        request = SandboxExecutionRequest(command="true", image_digest=PIN)
        result = await backend.execute(request)
        assert result.exit_code != 0
        assert "digest" in result.stderr.lower()

    @pytest.mark.asyncio
    async def test_inline_at_sha256_skips_inspect_when_no_override(self):
        # When the image string already carries '@sha256:...' and the
        # operator hasn't supplied an explicit override, Docker's own
        # resolver enforces the pin — we should not call the
        # digest_resolver at all. Test: a resolver that would *fail*
        # the match doesn't fire.
        called = {"count": 0}

        async def _resolver(_bin, _img):
            called["count"] += 1
            return OTHER

        async def _executor(req, session):
            return {"exit_code": 0, "stdout": "ok", "stderr": ""}

        opts = DockerSandboxBackendOptions(
            image=f"ghcr.io/foo/bar@{PIN}",
            digest_resolver=_resolver,
            executor=_executor,
        )
        backend = DockerSandboxBackend(opts)
        result = await backend.execute(SandboxExecutionRequest(command="true"))
        assert result.exit_code == 0
        assert called["count"] == 0

    @pytest.mark.asyncio
    async def test_inline_with_explicit_override_still_inspects(self):
        # If the operator pinned via @sha256 and *also* supplied an
        # expected_image_digest, we still cross-check. Mismatch refuses.
        async def _resolver(_bin, _img):
            return OTHER

        async def _executor(req, session):
            return {"exit_code": 0, "stdout": "ok", "stderr": ""}

        opts = DockerSandboxBackendOptions(
            image=f"ghcr.io/foo/bar@{PIN}",
            expected_image_digest=PIN,
            digest_resolver=_resolver,
            executor=_executor,
        )
        backend = DockerSandboxBackend(opts)
        result = await backend.execute(SandboxExecutionRequest(command="true"))
        assert result.exit_code != 0
        assert "digest" in result.stderr.lower()

    @pytest.mark.asyncio
    async def test_no_pin_anywhere_skips_verification(self):
        # No expected_image_digest, no @sha256 in image, no per-call
        # pin. The resolver must not be invoked.
        called = {"count": 0}

        async def _resolver(_bin, _img):
            called["count"] += 1
            return None

        async def _executor(req, session):
            return {"exit_code": 0, "stdout": "ok", "stderr": ""}

        opts = DockerSandboxBackendOptions(
            image="alpine:latest",
            digest_resolver=_resolver,
            executor=_executor,
        )
        backend = DockerSandboxBackend(opts)
        result = await backend.execute(SandboxExecutionRequest(command="true"))
        assert result.exit_code == 0
        assert called["count"] == 0


class TestExceptionDetails:
    @pytest.mark.asyncio
    async def test_image_digest_mismatch_carries_fields(self):
        backend = _backend(image="alpine:latest", expected=PIN, resolved=OTHER)
        # The verifier raises directly (the broad except in execute
        # converts to a result; the unit-level verifier we call here
        # is the typed one).
        with pytest.raises(ImageDigestMismatch) as excinfo:
            await backend._verify_image_digest(None)
        exc = excinfo.value
        assert exc.expected == PIN
        assert exc.actual == OTHER
        assert exc.image == "alpine:latest"

    @pytest.mark.asyncio
    async def test_unresolvable_actual_is_a_mismatch(self):
        # The digest resolver couldn't determine a digest (network
        # error, image not pulled, etc.). Fail-closed: treat as a
        # mismatch.
        backend = _backend(image="alpine:latest", expected=PIN, resolved=None)
        with pytest.raises(ImageDigestMismatch):
            await backend._verify_image_digest(None)
