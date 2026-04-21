import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type { GatewayOptions, SessionEntry } from "../types.js";
import type { RuntimeHooks, RuntimeEvent, AgentConfig, AgentState } from "../../types.js";

export function chatRoutes(
  sessions: Map<string, SessionEntry>,
  options: GatewayOptions,
): Hono {
  const app = new Hono();

  app.post("/", async (c) => {
    const { sessionId, message } = await c.req.json<{ sessionId: string; message: string }>();
    if (!sessionId || !message) {
      return c.json({ error: "sessionId and message are required" }, 400);
    }

    return streamSSE(c, async (stream) => {
      let approveResolve: (() => void) | null = null;

      const hooks: RuntimeHooks = {
        onEvent: async (event: RuntimeEvent, _config: AgentConfig, _state: AgentState) => {
          await stream.writeSSE({ data: JSON.stringify(event) });

          if (event.type === "loop_end" && event.reason === "pending_approval") {
            await new Promise<void>((resolve) => {
              approveResolve = resolve;
              const entry = sessions.get(sessionId);
              if (entry) entry.approveResolve = resolve;
            });
            const entry = sessions.get(sessionId);
            if (entry) {
              entry.runtime.approvePendingTool();
              entry.approveResolve = null;
              await entry.runtime.resume();
            }
          }
        },
      };

      let entry = sessions.get(sessionId);
      if (!entry) {
        const runtime = await options.createRuntime(sessionId, hooks);
        entry = { runtime, approveResolve: null };
        sessions.set(sessionId, entry);
      }

      try {
        await entry.runtime.runPrompt(message);
      } catch (err) {
        await stream.writeSSE({
          data: JSON.stringify({ type: "error", message: String(err) }),
        });
      } finally {
        approveResolve = null;
        await stream.writeSSE({ data: JSON.stringify({ type: "stream_end" }) });
      }
    });
  });

  app.post("/approve", async (c) => {
    const { sessionId } = await c.req.json<{ sessionId: string }>();
    const entry = sessions.get(sessionId);
    if (!entry) return c.json({ error: "session not found" }, 404);
    if (!entry.approveResolve) return c.json({ error: "no pending approval" }, 400);
    entry.approveResolve();
    return c.json({ ok: true });
  });

  return app;
}
