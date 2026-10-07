"""Entrypoint/CLI wiring for the gateway (design-review #12).

Covers the three fragmentation findings:

- the DEFAULT bind host is one value (loopback) and is configurable,
  rather than 127.0.0.1 in ``application.main`` vs 0.0.0.0 in
  ``server.run_gateway``;
- ``create_demo_gateway`` can wire an optional storage/retriever so the
  memory/jobs/logs routes stop returning 501 when a backend is supplied;
- the real application is reachable through a console script.
"""

from __future__ import annotations

from pathlib import Path
import tomllib

import pytest
import uvicorn
from fastapi.testclient import TestClient

from titanx.application import create_demo_gateway, main
from titanx.gateway import GatewayOptions
from titanx.gateway import server as gateway_server
from titanx.gateway.server import DEFAULT_HOST
from titanx.storage import LibSQLBackend


def test_default_bind_host_is_loopback() -> None:
    # One shared default: 127.0.0.1 is the safer choice for a local SDK;
    # 0.0.0.0 (server.run_gateway's old value) exposed every interface.
    assert DEFAULT_HOST == "127.0.0.1"


def test_run_gateway_binds_the_configured_host(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(app, host, port):  # noqa: ANN001 - uvicorn.run signature stand-in
        captured.update(host=host, port=port)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    gateway_server.run_gateway(
        GatewayOptions(port=4321, create_runtime=lambda *a: None), host="0.0.0.0"
    )
    assert captured == {"host": "0.0.0.0", "port": 4321}


def test_run_gateway_defaults_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(app, host, port):  # noqa: ANN001
        captured.update(host=host, port=port)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    gateway_server.run_gateway(GatewayOptions(create_runtime=lambda *a: None))
    assert captured["host"] == "127.0.0.1"


def test_web_main_binds_loopback_by_default(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(app, host, port):  # noqa: ANN001
        captured.update(host=host, port=port)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    assert main(["--web", "--data-dir", str(tmp_path), "--port", "4321"]) == 0
    assert captured == {"host": "127.0.0.1", "port": 4321}


def test_web_main_host_is_configurable(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(app, host, port):  # noqa: ANN001
        captured.update(host=host, port=port)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    assert main(["--web", "--data-dir", str(tmp_path), "--host", "0.0.0.0"]) == 0
    assert captured["host"] == "0.0.0.0"


def test_web_main_serves_memory_jobs_logs_not_501(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The shipped CLI should not advertise 501 on its own default: opening
    # the gateway wires a LibSQLBackend under the data dir so the memory/
    # jobs/logs routes are live without the host having to inject one.
    captured: dict[str, object] = {}

    def fake_run(app, host, port):  # noqa: ANN001
        captured.update(host=host, port=port)
        with TestClient(app) as client:
            captured["jobs"] = client.get("/api/jobs").status_code
            captured["logs"] = client.get("/api/logs").status_code
            captured["memory"] = client.get(
                "/api/memory", params={"sessionId": "s"}
            ).status_code

    monkeypatch.setattr(uvicorn, "run", fake_run)
    assert main(["--web", "--data-dir", str(tmp_path), "--port", "4321"]) == 0
    assert captured["jobs"] == 200
    assert captured["logs"] == 200
    assert captured["memory"] == 200


class _RecordingRetriever:
    """Injected retrieval boundary double; records the query it receives."""

    def __init__(self) -> None:
        self.queries: list[str] = []

    async def search(self, query, options):  # noqa: ANN001
        self.queries.append(query)
        return []


def _demo_storage(tmp_path: Path) -> LibSQLBackend:
    return LibSQLBackend(f"file:{tmp_path / 'store.db'}")


async def test_demo_gateway_serves_memory_jobs_logs_when_storage_is_supplied(tmp_path) -> None:
    storage = _demo_storage(tmp_path)
    await storage.initialize()
    retriever = _RecordingRetriever()
    app = create_demo_gateway(tmp_path / "gateway", storage=storage, retriever=retriever)

    with TestClient(app) as client:
        saved = client.post(
            "/api/memory", json={"sessionId": "s1", "content": "remember this"}
        )
        assert saved.status_code == 201

        listed = client.get("/api/memory", params={"sessionId": "s1"})
        assert listed.status_code == 200
        assert [row["content"] for row in listed.json()] == ["remember this"]

        searched = client.get("/api/memory", params={"q": "remember"})
        assert searched.status_code == 200
        assert retriever.queries == ["remember"]

        assert client.get("/api/jobs").status_code == 200
        assert client.get("/api/logs").status_code == 200


def test_demo_gateway_reports_501_without_storage(tmp_path) -> None:
    # Unchanged default: no backend configured -> the routes advertise it.
    app = create_demo_gateway(tmp_path / "gateway")
    with TestClient(app) as client:
        assert client.get("/api/jobs").status_code == 501
        assert client.get("/api/memory", params={"sessionId": "s"}).status_code == 501
        assert client.get("/api/logs").status_code == 501


def test_pyproject_exposes_the_application_entrypoint() -> None:
    root = Path(__file__).resolve().parents[1]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = data["project"]["scripts"]
    # The audit CLI keeps its name (non-breaking); the real application
    # gets its own console script so an installed package can reach it.
    assert scripts["titanx"] == "titanx.cli:main"
    assert scripts["titanx-app"] == "titanx.application:main"
