import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import type { GatewayOptions, SessionEntry } from "./types.js";
import { chatRoutes } from "./routes/chat.js";
import { memoryRoutes } from "./routes/memory.js";
import { jobRoutes } from "./routes/jobs.js";
import { logRoutes } from "./routes/logs.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export function createGateway(options: GatewayOptions): { start(): void; app: Hono } {
  const port = options.port ?? 3000;
  const sessions = new Map<string, SessionEntry>();
  const app = new Hono();

  app.use("*", cors());

  if (options.apiKey) {
    app.use("/api/*", async (c, next) => {
      const key = c.req.header("x-api-key");
      if (key !== options.apiKey) return c.json({ error: "unauthorized" }, 401);
      await next();
    });
  }

  app.route("/api/chat", chatRoutes(sessions, options));
  app.route("/api/memory", memoryRoutes(options));
  app.route("/api/jobs", jobRoutes(options));
  app.route("/api/logs", logRoutes(options));

  // Serve browser UI
  app.get("/", async (c) => {
    const uiPath = join(__dirname, "../../ui/index.html");
    try {
      const html = await readFile(uiPath, "utf8");
      return c.html(html);
    } catch {
      return c.text("TitanX Gateway running. UI not found at ui/index.html.", 200);
    }
  });

  return {
    app,
    start() {
      serve({ fetch: app.fetch, port }, () => {
        console.log(`TitanX Gateway listening on http://localhost:${port}`);
      });
    },
  };
}
