import { Hono } from "hono";
import type { GatewayOptions } from "../types.js";

export function logRoutes(options: GatewayOptions): Hono {
  const app = new Hono();

  app.get("/", async (c) => {
    if (!options.storage) return c.json({ error: "storage not configured" }, 501);
    const sessionId = c.req.query("sessionId");
    const limit = parseInt(c.req.query("limit") ?? "100", 10);
    const logs = await options.storage.listLogs(sessionId, limit);
    return c.json(logs);
  });

  return app;
}
