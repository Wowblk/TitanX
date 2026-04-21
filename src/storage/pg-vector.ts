import { randomUUID } from "node:crypto";
import type { PoolConfig } from "pg";
import type { JobEntry, LogEntry, MemoryEntry, ScoredMemory, StorageBackend } from "./types.js";

export class PgVectorBackend implements StorageBackend {
  private pool: import("pg").Pool | null = null;
  private hasVector = false;

  public constructor(private readonly config: PoolConfig) {}

  public async initialize(): Promise<void> {
    const { default: pg } = await import("pg");
    this.pool = new pg.Pool(this.config);

    const client = await this.pool.connect();
    try {
      try {
        await client.query("CREATE EXTENSION IF NOT EXISTS vector");
        this.hasVector = true;
      } catch {
        this.hasVector = false;
      }

      await client.query(`
        CREATE TABLE IF NOT EXISTS memories (
          id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          content TEXT NOT NULL,
          role TEXT NOT NULL,
          created_at TIMESTAMPTZ DEFAULT NOW(),
          embedding TEXT
        )
      `);

      if (this.hasVector) {
        await client.query(`
          ALTER TABLE memories ADD COLUMN IF NOT EXISTS embedding_vec vector(1536)
        `).catch(() => {});
        await client.query(`
          CREATE INDEX IF NOT EXISTS memories_vec_idx
            ON memories USING ivfflat (embedding_vec vector_cosine_ops)
        `).catch(() => {});
      }

      await client.query(`
        CREATE TABLE IF NOT EXISTS jobs (
          id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          type TEXT NOT NULL,
          payload JSONB,
          result JSONB,
          error TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW(),
          updated_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id TEXT PRIMARY KEY,
          timestamp TIMESTAMPTZ NOT NULL,
          event TEXT NOT NULL,
          actor TEXT NOT NULL,
          session_id TEXT,
          data JSONB
        )
      `);
    } finally {
      client.release();
    }
  }

  private get db(): import("pg").Pool {
    if (!this.pool) throw new Error("PgVectorBackend not initialized");
    return this.pool;
  }

  public async saveMemory(entry: Omit<MemoryEntry, "id" | "createdAt">): Promise<MemoryEntry> {
    const id = randomUUID();
    const embeddingJson = entry.embedding ? JSON.stringify(entry.embedding) : null;
    await this.db.query(
      `INSERT INTO memories (id, session_id, content, role, embedding) VALUES ($1, $2, $3, $4, $5)`,
      [id, entry.sessionId, entry.content, entry.role, embeddingJson],
    );
    if (this.hasVector && entry.embedding) {
      await this.db.query(
        `UPDATE memories SET embedding_vec = $1::vector WHERE id = $2`,
        [`[${entry.embedding.join(",")}]`, id],
      ).catch(() => {});
    }
    return { ...entry, id, createdAt: new Date() };
  }

  public async searchByVector(embedding: number[], sessionId?: string, limit = 10): Promise<ScoredMemory[]> {
    if (!this.hasVector) return [];
    const vec = `[${embedding.join(",")}]`;
    const params: unknown[] = [vec, limit];
    const where = sessionId ? "AND session_id = $3" : "";
    if (sessionId) params.push(sessionId);
    const res = await this.db.query(
      `SELECT *, 1 - (embedding_vec <=> $1::vector) AS score
       FROM memories
       WHERE embedding_vec IS NOT NULL ${where}
       ORDER BY embedding_vec <=> $1::vector
       LIMIT $2`,
      params,
    );
    return res.rows.map((r) => this.rowToMemory(r, parseFloat(r.score), "vector"));
  }

  public async searchByFTS(query: string, sessionId?: string, limit = 10): Promise<ScoredMemory[]> {
    const params: unknown[] = [query, limit];
    const where = sessionId ? "AND session_id = $3" : "";
    if (sessionId) params.push(sessionId);
    const res = await this.db.query(
      `SELECT *, ts_rank(to_tsvector('english', content), plainto_tsquery('english', $1)) AS score
       FROM memories
       WHERE to_tsvector('english', content) @@ plainto_tsquery('english', $1) ${where}
       ORDER BY score DESC
       LIMIT $2`,
      params,
    );
    return res.rows.map((r) => this.rowToMemory(r, parseFloat(r.score), "fts"));
  }

  public async listMemories(sessionId: string, limit = 50): Promise<MemoryEntry[]> {
    const res = await this.db.query(
      `SELECT * FROM memories WHERE session_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [sessionId, limit],
    );
    return res.rows.map((r) => this.rowToMemory(r, 0, "fts"));
  }

  public async saveJob(entry: Omit<JobEntry, "id" | "createdAt" | "updatedAt">): Promise<JobEntry> {
    const id = randomUUID();
    const now = new Date();
    await this.db.query(
      `INSERT INTO jobs (id, session_id, status, type, payload) VALUES ($1, $2, $3, $4, $5)`,
      [id, entry.sessionId, entry.status, entry.type, JSON.stringify(entry.payload ?? null)],
    );
    return { ...entry, id, createdAt: now, updatedAt: now };
  }

  public async updateJob(id: string, update: Partial<Pick<JobEntry, "status" | "result" | "error">>): Promise<void> {
    const sets: string[] = ["updated_at = NOW()"];
    const params: unknown[] = [];
    let i = 1;
    if (update.status !== undefined) { sets.push(`status = $${i++}`); params.push(update.status); }
    if (update.result !== undefined) { sets.push(`result = $${i++}`); params.push(JSON.stringify(update.result)); }
    if (update.error !== undefined) { sets.push(`error = $${i++}`); params.push(update.error); }
    params.push(id);
    await this.db.query(`UPDATE jobs SET ${sets.join(", ")} WHERE id = $${i}`, params);
  }

  public async listJobs(sessionId?: string): Promise<JobEntry[]> {
    const res = sessionId
      ? await this.db.query(`SELECT * FROM jobs WHERE session_id = $1 ORDER BY created_at DESC`, [sessionId])
      : await this.db.query(`SELECT * FROM jobs ORDER BY created_at DESC`);
    return res.rows.map((r) => ({
      id: r.id,
      sessionId: r.session_id,
      status: r.status,
      type: r.type,
      payload: r.payload,
      result: r.result,
      error: r.error,
      createdAt: new Date(r.created_at),
      updatedAt: new Date(r.updated_at),
    }));
  }

  public async saveLog(entry: Omit<LogEntry, "id">): Promise<void> {
    await this.db.query(
      `INSERT INTO audit_logs (id, timestamp, event, actor, session_id, data) VALUES ($1, $2, $3, $4, $5, $6)`,
      [randomUUID(), entry.timestamp, entry.event, entry.actor, entry.sessionId ?? null, JSON.stringify(entry.data ?? null)],
    );
  }

  public async listLogs(sessionId?: string, limit = 100): Promise<LogEntry[]> {
    const res = sessionId
      ? await this.db.query(`SELECT * FROM audit_logs WHERE session_id = $1 ORDER BY timestamp DESC LIMIT $2`, [sessionId, limit])
      : await this.db.query(`SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT $1`, [limit]);
    return res.rows.map((r) => ({
      id: r.id,
      timestamp: new Date(r.timestamp),
      event: r.event,
      actor: r.actor,
      sessionId: r.session_id ?? undefined,
      data: r.data,
    }));
  }

  private rowToMemory(r: Record<string, unknown>, score: number, source: "vector" | "fts"): ScoredMemory {
    return {
      id: r.id as string,
      sessionId: r.session_id as string,
      content: r.content as string,
      role: r.role as string,
      createdAt: new Date(r.created_at as string),
      embedding: r.embedding ? JSON.parse(r.embedding as string) : undefined,
      score,
      source,
    };
  }
}
