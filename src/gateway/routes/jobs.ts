import { Hono } from "hono";
import type { GatewayOptions } from "../types.js";

export function jobRoutes(options: GatewayOptions): Hono {
  const app = new Hono();

  app.get("/", async (c) => {
    if (!options.storage) return c.json({ error: "storage not configured" }, 501);
    const sessionId = c.req.query("sessionId");
    const jobs = await options.storage.listJobs(sessionId);
    return c.json(jobs);
  });

  app.post("/", async (c) => {
    if (!options.storage) return c.json({ error: "storage not configured" }, 501);
    const body = await c.req.json<{ sessionId: string; type: string; payload?: unknown }>();
    if (!body.sessionId || !body.type) {
      return c.json({ error: "sessionId and type are required" }, 400);
    }
    const job = await options.storage.saveJob({
      sessionId: body.sessionId,
      type: body.type,
      status: "pending",
      payload: body.payload,
    });
    return c.json(job, 201);
  });

  app.patch("/:id", async (c) => {
    if (!options.storage) return c.json({ error: "storage not configured" }, 501);
    const id = c.req.param("id");
    const body = await c.req.json<{ status?: string; result?: unknown; error?: string }>();
    await options.storage.updateJob(id, {
      status: body.status as "pending" | "running" | "completed" | "failed" | undefined,
      result: body.result,
      error: body.error,
    });
    return c.json({ ok: true });
  });

  return app;
}
