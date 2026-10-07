from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from ..runtime import AgentRuntime
from ..types import RuntimeHooks
from ..storage.types import StorageBackend
from ..retrieval.hybrid import HybridRetriever


@dataclass
class GatewayOptions:
    port: int = 3000
    api_key: str | None = None
    storage: StorageBackend | None = None
    retriever: HybridRetriever | None = None
    create_runtime: Callable[
        [str, RuntimeHooks],
        AgentRuntime | Awaitable[AgentRuntime],
    ] | Callable[
        [str, RuntimeHooks, dict[str, Any]],
        AgentRuntime | Awaitable[AgentRuntime],
    ] = None  # type: ignore[assignment]


@dataclass
class SessionEntry:
    runtime: AgentRuntime
    approve_event: object  # asyncio.Event — typed as object to avoid import cycle
