import { Hono } from "hono";
import type { GatewayOptions } from "../types.js";

export function memoryRoutes(options: GatewayOptions): Hono {
  const app = new Hono();

  app.get("/", async (c) => {
    if (!options.storage) return c.json({ error: "storage not configured" }, 501);
    const sessionId = c.req.query("sessionId");
    const query = c.req.query("q");
    const limit = parseInt(c.req.query("limit") ?? "20", 10);

    if (query) {
      if (options.retriever) {
        const results = await options.retriever.search(query, { sessionId, limit });
        return c.json(results);
      }
      const results = await options.storage.searchByFTS(query, sessionId, limit);
      return c.json(results);
    }

    if (!sessionId) return c.json({ error: "sessionId required for listing" }, 400);
    const entries = await options.storage.listMemories(sessionId, limit);
    return c.json(entries);
  });

  app.post("/", async (c) => {
    if (!options.storage) return c.json({ error: "storage not configured" }, 501);
    const body = await c.req.json<{ sessionId: string; content: string; role?: string }>();
    if (!body.sessionId || !body.content) {
      return c.json({ error: "sessionId and content are required" }, 400);
    }
    const entry = await options.storage.saveMemory({
      sessionId: body.sessionId,
      content: body.content,
      role: body.role ?? "user",
    });
    return c.json(entry, 201);
  });

  return app;
}
