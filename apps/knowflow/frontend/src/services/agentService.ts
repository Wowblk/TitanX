import { getBaseUrl } from "./apiClient";

export type AgentEvent =
  | { type: "assistant_text"; text: string }
  | { type: "assistant_tool_calls"; tool_calls?: unknown[] }
  | { type: "tool_result"; tool_name?: string; is_error?: boolean }
  | { type: "error"; message: string }
  | { type: "stream_end" }
  | { type: string; [key: string]: unknown };

export type StreamChatOptions = {
  sessionId: string;
  message: string;
  signal?: AbortSignal;
  onEvent: (event: AgentEvent) => void;
};

const getStoredAccessToken = (): string | null => {
  try {
    const raw = localStorage.getItem("knowflow_auth_tokens");
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { accessToken?: string };
    return parsed.accessToken ?? null;
  } catch {
    return null;
  }
};

const parseSseChunk = (buffer: string, onEvent: (event: AgentEvent) => void) => {
  const events = buffer.split(/\n\n/);
  const remainder = events.pop() ?? "";
  for (const event of events) {
    const dataLines = event
      .split(/\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim());
    if (!dataLines.length) continue;
    try {
      onEvent(JSON.parse(dataLines.join("\n")) as AgentEvent);
    } catch {
      onEvent({ type: "error", message: dataLines.join("\n") });
    }
  }
  return remainder;
};

export const agentService = {
  async streamChat({ sessionId, message, signal, onEvent }: StreamChatOptions) {
    const token = getStoredAccessToken();
    if (!token) {
      onEvent({ type: "error", message: "请先登录后使用 KnowFlow AI 助手" });
      onEvent({ type: "stream_end" });
      return;
    }

    const baseUrl = getBaseUrl();
    const response = await fetch(`${baseUrl}/api/v1/agent/chat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ sessionId, message }),
      credentials: "include",
      signal,
    });

    if (!response.ok || !response.body) {
      onEvent({ type: "error", message: `AI 助手请求失败：${response.status}` });
      onEvent({ type: "stream_end" });
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      buffer = parseSseChunk(buffer, onEvent);
    }
    buffer += decoder.decode();
    if (buffer.trim()) {
      parseSseChunk(`${buffer}\n\n`, onEvent);
    }
  },
};
