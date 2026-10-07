from __future__ import annotations

import asyncio
import json
from typing import Any

from titanx.tools.knowflow import KnowFlowToolClient, KnowFlowToolRuntime


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


class _UrlopenRecorder:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: float) -> _FakeResponse:
        self.requests.append((request, timeout))
        return _FakeResponse(self.payload)


def test_search_posts_calls_knowflow_search_api(monkeypatch: Any) -> None:
    recorder = _UrlopenRecorder({"items": [{"id": "42", "title": "网关"}]})
    monkeypatch.setattr("titanx.tools.knowflow.urlopen", recorder)

    runtime = KnowFlowToolRuntime(KnowFlowToolClient(
        base_url="http://127.0.0.1:8080",
        bearer_token="jwt-token",
    ))

    result = asyncio.run(runtime.execute("knowflow_search_posts", {"query": "网关", "size": 20}))

    assert result.error is None
    request, _ = recorder.requests[0]
    assert request.full_url == "http://127.0.0.1:8080/api/v1/search?q=%E7%BD%91%E5%85%B3&size=10"
    assert request.get_header("Authorization") == "Bearer jwt-token"
    assert json.loads(result.output)["items"][0]["title"] == "网关"


def test_create_draft_posts_to_agent_tool_endpoint(monkeypatch: Any) -> None:
    recorder = _UrlopenRecorder({"draftId": "1001"})
    monkeypatch.setattr("titanx.tools.knowflow.urlopen", recorder)

    runtime = KnowFlowToolRuntime(KnowFlowToolClient(
        base_url="http://localhost:8380",
        bearer_token="jwt-token",
    ))

    result = asyncio.run(runtime.execute(
        "knowflow_create_draft",
        {"title": "标题", "content": "正文", "description": "摘要", "tags": ["AI"]},
    ))

    assert result.error is None
    request, _ = recorder.requests[0]
    assert request.full_url == "http://localhost:8380/api/v1/agent/tools/drafts"
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert json.loads(request.data.decode("utf-8"))["title"] == "标题"
    assert json.loads(result.output)["draftId"] == "1001"


def test_knowflow_tools_return_directly() -> None:
    runtime = KnowFlowToolRuntime(KnowFlowToolClient(
        base_url="http://localhost:8380",
        bearer_token="jwt-token",
    ))

    tools = {item.name: item for item in runtime.list_tools()}

    assert tools["knowflow_search_posts"].metadata["return_direct"] is True
    assert tools["knowflow_get_post_detail"].metadata["return_direct"] is True
    assert tools["knowflow_get_my_posts"].metadata["return_direct"] is True
    assert tools["knowflow_create_draft"].metadata["return_direct"] is True
