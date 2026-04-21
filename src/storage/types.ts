export interface MemoryEntry {
  id: string;
  sessionId: string;
  content: string;
  role: string;
  createdAt: Date;
  embedding?: number[];
}

export interface JobEntry {
  id: string;
  sessionId: string;
  status: "pending" | "running" | "completed" | "failed";
  type: string;
  payload?: unknown;
  result?: unknown;
  error?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface LogEntry {
  id: string;
  timestamp: Date;
  event: string;
  actor: string;
  sessionId?: string;
  data?: unknown;
}

export interface ScoredMemory extends MemoryEntry {
  score: number;
  source: "vector" | "fts";
}

export interface StorageBackend {
  initialize(): Promise<void>;

  saveMemory(entry: Omit<MemoryEntry, "id" | "createdAt">): Promise<MemoryEntry>;
  searchByVector(embedding: number[], sessionId?: string, limit?: number): Promise<ScoredMemory[]>;
  searchByFTS(query: string, sessionId?: string, limit?: number): Promise<ScoredMemory[]>;
  listMemories(sessionId: string, limit?: number): Promise<MemoryEntry[]>;

  saveJob(entry: Omit<JobEntry, "id" | "createdAt" | "updatedAt">): Promise<JobEntry>;
  updateJob(id: string, update: Partial<Pick<JobEntry, "status" | "result" | "error">>): Promise<void>;
  listJobs(sessionId?: string): Promise<JobEntry[]>;

  saveLog(entry: Omit<LogEntry, "id">): Promise<void>;
  listLogs(sessionId?: string, limit?: number): Promise<LogEntry[]>;
}
