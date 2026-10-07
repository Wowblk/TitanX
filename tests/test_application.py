"""Unified application defaults exercised through terminal and gateway entry points."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from uuid import UUID

from fastapi.testclient import TestClient
import pytest

from titanx.application import DemoApplication, create_demo_gateway, main
from titanx.types import RuntimeHooks


def _prompt(index: int) -> str:
    return f"observation-{index:02d}: " + "x" * 600


def _sse_events(body: str) -> list[dict]:
    return [
        json.loads(line.removeprefix("data:").strip())
        for line in body.splitlines()
        if line.startswith("data:")
    ]


async def test_default_runtime_compacts_naturally_and_keeps_originals(tmp_path):
    application = DemoApplication(tmp_path)
    events = []
    runtime = application.create_runtime(
        RuntimeHooks(on_event=lambda event, config, state: events.append(event)),
    )
    try:
        await runtime.run_prompt(_prompt(0))
        original = next(message for message in runtime.state.messages if message.role == "user")
        for index in range(1, 20):
            await runtime.run_prompt(_prompt(index))

        compactions = [event for event in events if event.type == "compaction_triggered"]
        assert compactions
        assert all(event.input_tokens_after <= event.target_tokens for event in compactions)
        assert [event.reason for event in events if event.type == "loop_end"] == ["completed"] * 20
        assert original.id not in {message.id for message in runtime.state.messages}
        matches = await application.store.search(runtime.config.session_id, "observation-00")
        assert original.id in {match["message_id"] for match in matches}
        page = await application.store.read(runtime.config.session_id, "message", original.id)
        assert json.loads(page.content)["content"] == _prompt(0)
        assert runtime.state.last_text_response == f"Echo: {_prompt(19)}"
    finally:
        await application.close()


def test_gateway_shares_defaults_isolates_sessions_and_closes_store(tmp_path, monkeypatch):
    data_dir = tmp_path / "gateway"
    app = create_demo_gateway(data_dir)
    assert not data_dir.exists()
    assert not hasattr(app.state, "titanx_application")

    runtimes = []
    with TestClient(app) as client:
        application = app.state.titanx_application
        store = application.store
        assert (data_dir / "context.sqlite").is_file()
        create_runtime = application.create_runtime

        def record_runtime(hooks):
            runtime = create_runtime(hooks)
            runtimes.append(runtime)
            return runtime

        monkeypatch.setattr(application, "create_runtime", record_runtime)
        all_events = []
        for index in range(20):
            response = client.post("/api/chat", json={"sessionId": "browser-a", "message": _prompt(index)})
            assert response.status_code == 200
            events = _sse_events(response.text)
            assert events[-1] == {"type": "stream_end"}
            assert [event["reason"] for event in events if event["type"] == "loop_end"] == ["completed"]
            assert [event["text"] for event in events if event["type"] == "assistant_text"] == [f"Echo: {_prompt(index)}"]
            all_events.extend(events)
        assert len(runtimes) == 1
        assert any(event["type"] == "compaction_triggered" for event in all_events)

        response = client.post("/api/chat", json={"sessionId": "browser-b", "message": "separate session"})
        assert response.status_code == 200
        assert len(runtimes) == 2
        session_ids = {runtime.config.session_id for runtime in runtimes}
        assert len(session_ids) == 2
        assert session_ids.isdisjoint({"browser-a", "browser-b"})
        for session_id in session_ids:
            assert str(UUID(session_id)) == session_id
        assert not any(message.content == "separate session" for message in runtimes[0].state.messages)

        response = client.post("/api/chat", json={"sessionId": "browser-a", "message": "z" * 25000})
        assert response.status_code == 200
        events = _sse_events(response.text)
        assert any(event["type"] == "compaction_blocked" for event in events)
        reasons = [event["reason"] for event in events if event["type"] == "loop_end"]
        assert reasons and all(reason not in {"completed", "pending_approval"} for reason in reasons)
        assert not any(event["type"] == "assistant_text" for event in events)
        assert events[-1] == {"type": "stream_end"}
        assert len(runtimes) == 2

    assert not hasattr(app.state, "titanx_application")
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        asyncio.run(store.search(runtimes[0].config.session_id, "observation"))


def test_single_prompt_cli_returns_failure_when_context_is_blocked(tmp_path, capsys):
    assert main(["--data-dir", str(tmp_path), "z" * 25000]) == 1
    output = capsys.readouterr()
    assert "[已停止]" in output.err
    assert "Echo:" not in output.out
    assert (tmp_path / "context.sqlite").is_file()


def test_gateway_shutdown_tears_down_every_session():
    from titanx.gateway import GatewayOptions, create_gateway

    torn_down = []

    class _RecordingRuntime:
        async def run_prompt(self, message, *, hooks=None):
            return None

        async def aclose(self):
            torn_down.append(self)

    def create_runtime(_session_id, _hooks):
        return _RecordingRuntime()

    app = create_gateway(GatewayOptions(create_runtime=create_runtime))
    with TestClient(app) as client:
        for session_id in ("s1", "s2"):
            response = client.post("/api/chat", json={"sessionId": session_id, "message": "hi"})
            assert response.status_code == 200

    assert len(torn_down) == 2


async def test_runtime_aclose_removes_session_rows_and_is_idempotent(tmp_path):
    application = DemoApplication(tmp_path)
    runtime = application.create_runtime()
    try:
        await runtime.run_prompt("remember this exact phrase")
        session_id = runtime.config.session_id
        assert await application.store.search(session_id, "exact phrase")

        await runtime.aclose()
        # The per-session rows are gone, then a second call must be a no-op.
        assert await application.store.search(session_id, "exact phrase") == []
        await runtime.aclose()
    finally:
        await application.close()


def test_unified_and_legacy_help_have_no_storage_side_effects(tmp_path):
    project = Path(__file__).resolve().parents[1]
    for entry in ("run.py", "demo.py", "run_gateway.py", "demo_context.py"):
        result = subprocess.run(
            [sys.executable, str(project / entry), "--help"],
            cwd=tmp_path, capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert "--data-dir" in result.stdout
    assert not (tmp_path / ".titanx").exists()
