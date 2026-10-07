from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from titanx.types import ToolDefinition, ToolExecutionResult, ToolRuntime


def _schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


@dataclass(frozen=True)
class KnowFlowToolClient:
    base_url: str
    bearer_token: str
    timeout: float = 20.0

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return await asyncio.to_thread(self._request, "GET", path, params, None)

    async def post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        return await asyncio.to_thread(self._request, "POST", path, None, body or {})

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        body: dict[str, Any] | None,
    ) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}{path}"
        if params:
            cleaned = {key: value for key, value in params.items() if value is not None and value != ""}
            if cleaned:
                url = f"{url}?{urlencode(cleaned)}"

        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(url, data=data, method=method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.bearer_token:
            request.add_header("Authorization", f"Bearer {self.bearer_token}")

        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                if not raw:
                    return {"ok": True}
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {"data": parsed}
        except HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"KnowFlow API {method} {path} failed: HTTP {exc.code} {raw}") from exc
        except URLError as exc:
            raise RuntimeError(f"KnowFlow API {method} {path} unavailable: {exc.reason}") from exc


class KnowFlowToolRuntime(ToolRuntime):
    def __init__(self, client: KnowFlowToolClient) -> None:
        self._client = client

    def list_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name="knowflow_search_posts",
                description="Search public KnowFlow knowledge posts by keyword.",
                parameters=_schema(
                    {
                        "query": {"type": "string", "description": "Search keywords."},
                        "size": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
                    },
                    ["query"],
                ),
                return_direct=True,
            ),
            ToolDefinition(
                name="knowflow_get_post_detail",
                description="Get the detail of a KnowFlow knowledge post by id.",
                parameters=_schema(
                    {"post_id": {"type": "string", "description": "Knowledge post id."}},
                    ["post_id"],
                ),
                return_direct=True,
            ),
            ToolDefinition(
                name="knowflow_get_my_posts",
                description="List the current user's published KnowFlow posts.",
                parameters=_schema(
                    {
                        "page": {"type": "integer", "minimum": 1, "default": 1},
                        "size": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
                    }
                ),
                return_direct=True,
            ),
            ToolDefinition(
                name="knowflow_create_draft",
                description=(
                    "Create a private draft knowledge post for the current user. "
                    "Use this only when the user clearly asks to draft or save content."
                ),
                parameters=_schema(
                    {
                        "title": {"type": "string", "description": "Draft title."},
                        "content": {"type": "string", "description": "Draft body content."},
                        "description": {"type": "string", "description": "Short summary."},
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional tags.",
                        },
                    },
                    ["title", "content"],
                ),
                return_direct=True,
            ),
        ]

    async def execute(self, name: str, params: dict[str, Any]) -> ToolExecutionResult:
        try:
            output = await self._execute(name, params)
        except Exception as exc:
            return ToolExecutionResult(output=str(exc), error=type(exc).__name__)
        return ToolExecutionResult(output=self._format_output(name, output))

    def _format_output(self, name: str, data: dict[str, Any]) -> str:
        """Render a tool result as the assistant's own reply.

        The KnowFlow tools are ``return_direct``, so their output is shown to the
        user verbatim instead of being summarised by the LLM. Keep the wording
        here (application side); the SDK only ends the turn on the output.
        """
        if name == "knowflow_search_posts":
            items = data.get("items") or []
            if not items:
                return "没有找到相关知文。你可以换一个关键词再试。"
            lines = ["找到这些相关知文："]
            for item in items[:5]:
                title = item.get("title") or "未命名知文"
                post_id = item.get("id") or ""
                description = item.get("description") or ""
                suffix = f"：{description}" if description else ""
                lines.append(f"- {title}（ID：{post_id}）{suffix}")
            return "\n".join(lines)

        if name == "knowflow_get_my_posts":
            items = data.get("items") or []
            if not items:
                return "你目前没有已发布的知文。草稿不会出现在“已发布内容”列表里。"
            lines = ["你已发布的知文有："]
            for item in items[:10]:
                title = item.get("title") or "未命名知文"
                post_id = item.get("id") or ""
                description = item.get("description") or ""
                suffix = f"：{description}" if description else ""
                lines.append(f"- {title}（ID：{post_id}）{suffix}")
            return "\n".join(lines)

        if name == "knowflow_get_post_detail":
            title = data.get("title") or "未命名知文"
            post_id = data.get("id") or ""
            description = data.get("description") or "暂无摘要"
            tags = data.get("tags") or []
            tag_text = "、".join(tags) if tags else "无标签"
            return f"{title}（ID：{post_id}）\n摘要：{description}\n标签：{tag_text}"

        if name == "knowflow_create_draft":
            draft_id = data.get("draftId")
            if draft_id:
                return f"草稿已创建成功，草稿 ID：{draft_id}。你可以到创作/我的草稿里继续编辑。"
            return "草稿已创建成功。你可以到创作/我的草稿里继续编辑。"

        return json.dumps(data, ensure_ascii=False)

    async def _execute(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        if name == "knowflow_search_posts":
            return await self._client.get(
                "/api/v1/search",
                {"q": params.get("query", ""), "size": min(int(params.get("size") or 5), 10)},
            )
        if name == "knowflow_get_post_detail":
            post_id = str(params.get("post_id") or "").strip()
            if not post_id:
                raise ValueError("post_id is required")
            return await self._client.get(f"/api/v1/knowposts/detail/{post_id}")
        if name == "knowflow_get_my_posts":
            return await self._client.get(
                "/api/v1/knowposts/mine",
                {
                    "page": max(int(params.get("page") or 1), 1),
                    "size": min(max(int(params.get("size") or 5), 1), 10),
                },
            )
        if name == "knowflow_create_draft":
            return await self._client.post("/api/v1/agent/tools/drafts", params)
        raise ValueError(f"Unknown KnowFlow tool: {name}")
