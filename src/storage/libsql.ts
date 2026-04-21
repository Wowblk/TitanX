import { randomUUID } from "node:crypto";
import type { JobEntry, LogEntry, MemoryEntry, ScoredMemory, StorageBackend } from "./types.js";

function cosineSimilarity(a: number[], b: number[]): number {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  return denom === 0 ? 0 : dot / denom;
}

export interface LibSQLConfig {
  url: string;
  authToken?: string;
}

export class LibSQLBackend implements StorageBackend {
  private client: import("@libsql/client").Client | null = null;

  public constructor(private readonly config: LibSQLConfig) {}

  public async initialize(): Promise<void> {
    const { createClient } = await import("@libsql/client");
    this.client = createClient(this.config);

    await this.db.execute(`
      CREATE TABLE IF NOT EXISTS memories (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        content TEXT NOT NULL,
        role TEXT NOT NULL,
        embedding TEXT,
        created_at TEXT NOT NULL
      )
    `);

    await this.db.execute(`
      CREATE TABLE IF NOT EXISTS memories_fts USING fts5(content, content=memories, content_rowid=rowid)
    `).catch(() => {
      // FTS5 may already exist or not be supported — fall back to LIKE search
    });

    await this.db.execute(`
      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        type TEXT NOT NULL,
        payload TEXT,
        result TEXT,
        error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    await this.db.execute(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event TEXT NOT NULL,
        actor TEXT NOT NULL,
        session_id TEXT,
        data TEXT
      )
    `);
  }

  private get db(): import("@libsql/client").Client {
    if (!this.client) throw new Error("LibSQLBackend not initialized");
    return this.client;
  }

  public async saveMemory(entry: Omit<MemoryEntry, "id" | "createdAt">): Promise<MemoryEntry> {
    const id = randomUUID();
    const now = new Date();
    await this.db.execute({
      sql: `INSERT INTO memories (id, session_id, content, role, embedding, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
      args: [id, entry.sessionId, entry.content, entry.role, entry.embedding ? JSON.stringify(entry.embedding) : null, now.toISOString()],
    });
    return { ...entry, id, createdAt: now };
  }

  public async searchByVector(embedding: number[], sessionId?: string, limit = 10): Promise<ScoredMemory[]> {
    const sql = sessionId
      ? `SELECT * FROM memories WHERE session_id = ? AND embedding IS NOT NULL`
      : `SELECT * FROM memories WHERE embedding IS NOT NULL`;
    const args = sessionId ? [sessionId] : [];
    const res = await this.db.execute({ sql, args });

    return res.rows
      .map((r) => {
        const emb = r.embedding ? JSON.parse(r.embedding as string) as number[] : null;
        const score = emb ? cosineSimilarity(embedding, emb) : 0;
        return { row: r, score };
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map(({ row: r, score }) => ({
        id: r.id as string,
        sessionId: r.session_id as string,
        content: r.content as string,
        role: r.role as string,
        createdAt: new Date(r.created_at as string),
        embedding: r.embedding ? JSON.parse(r.embedding as string) : undefined,
        score,
        source: "vector" as const,
      }));
  }

  public async searchByFTS(query: string, sessionId?: string, limit = 10): Promise<ScoredMemory[]> {
    const pattern = `%${query}%`;
    const sql = sessionId
      ? `SELECT * FROM memories WHERE content LIKE ? AND session_id = ? ORDER BY created_at DESC LIMIT ?`
      : `SELECT * FROM memories WHERE content LIKE ? ORDER BY created_at DESC LIMIT ?`;
    const args = sessionId ? [pattern, sessionId, limit] : [pattern, limit];
    const res = await this.db.execute({ sql, args });

    return res.rows.map((r) => ({
      id: r.id as string,
      sessionId: r.session_id as string,
      content: r.content as string,
      role: r.role as string,
      createdAt: new Date(r.created_at as string),
      embedding: r.embedding ? JSON.parse(r.embedding as string) : undefined,
      score: 1.0,
      source: "fts" as const,
    }));
  }

  public async listMemories(sessionId: string, limit = 50): Promise<MemoryEntry[]> {
    const res = await this.db.execute({
      sql: `SELECT * FROM memories WHERE session_id = ? ORDER BY created_at DESC LIMIT ?`,
      args: [sessionId, limit],
    });
    return res.rows.map((r) => ({
      id: r.id as string,
      sessionId: r.session_id as string,
      content: r.content as string,
      role: r.role as string,
      createdAt: new Date(r.created_at as string),
      embedding: r.embedding ? JSON.parse(r.embedding as string) : undefined,
    }));
  }

  public async saveJob(entry: Omit<JobEntry, "id" | "createdAt" | "updatedAt">): Promise<JobEntry> {
    const id = randomUUID();
    const now = new Date();
    await this.db.execute({
      sql: `INSERT INTO jobs (id, session_id, status, type, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [id, entry.sessionId, entry.status, entry.type, JSON.stringify(entry.payload ?? null), now.toISOString(), now.toISOString()],
    });
    return { ...entry, id, createdAt: now, updatedAt: now };
  }

  public async updateJob(id: string, update: Partial<Pick<JobEntry, "status" | "result" | "error">>): Promise<void> {
    const now = new Date().toISOString();
    if (update.status !== undefined) {
      await this.db.execute({ sql: `UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?`, args: [update.status, now, id] });
    }
    if (update.result !== undefined) {
      await this.db.execute({ sql: `UPDATE jobs SET result = ?, updated_at = ? WHERE id = ?`, args: [JSON.stringify(update.result), now, id] });
    }
    if (update.error !== undefined) {
      await this.db.execute({ sql: `UPDATE jobs SET error = ?, updated_at = ? WHERE id = ?`, args: [update.error, now, id] });
    }
  }

  public async listJobs(sessionId?: string): Promise<JobEntry[]> {
    const res = sessionId
      ? await this.db.execute({ sql: `SELECT * FROM jobs WHERE session_id = ? ORDER BY created_at DESC`, args: [sessionId] })
      : await this.db.execute(`SELECT * FROM jobs ORDER BY created_at DESC`);
    return res.rows.map((r) => ({
      id: r.id as string,
      sessionId: r.session_id as string,
      status: r.status as JobEntry["status"],
      type: r.type as string,
      payload: r.payload ? JSON.parse(r.payload as string) : undefined,
      result: r.result ? JSON.parse(r.result as string) : undefined,
      error: r.error as string | undefined,
      createdAt: new Date(r.created_at as string),
      updatedAt: new Date(r.updated_at as string),
    }));
  }

  public async saveLog(entry: Omit<LogEntry, "id">): Promise<void> {
    await this.db.execute({
      sql: `INSERT INTO audit_logs (id, timestamp, event, actor, session_id, data) VALUES (?, ?, ?, ?, ?, ?)`,
      args: [randomUUID(), entry.timestamp.toISOString(), entry.event, entry.actor, entry.sessionId ?? null, JSON.stringify(entry.data ?? null)],
    });
  }

  public async listLogs(sessionId?: string, limit = 100): Promise<LogEntry[]> {
    const res = sessionId
      ? await this.db.execute({ sql: `SELECT * FROM audit_logs WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?`, args: [sessionId, limit] })
      : await this.db.execute({ sql: `SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?`, args: [limit] });
    return res.rows.map((r) => ({
      id: r.id as string,
      timestamp: new Date(r.timestamp as string),
      event: r.event as string,
      actor: r.actor as string,
      sessionId: r.session_id as string | undefined,
      data: r.data ? JSON.parse(r.data as string) : undefined,
    }));
  }
}
