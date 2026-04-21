import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

import { SandboxRouter } from "./router.js";
import { isPathAllowed } from "./path-guard.js";
import type {
  ManagedSandboxSession,
  SandboxBackend,
  SandboxExecutionRequest,
  SandboxExecutionResult,
  SandboxFileEntry,
  SandboxRouterInput,
  SandboxSession,
  SandboxSnapshot,
} from "./types.js";

export class SandboxSessionManager {
  private readonly sessions = new Map<string, ManagedSandboxSession>();
  private readonly sessionBackends = new Map<string, SandboxBackend>();
  private readonly workspacePaths = new Map<string, string>();

  public constructor(
    private readonly router: SandboxRouter,
    private readonly workspaceDir?: string,
    private readonly allowedWritePaths?: string[],
  ) {}

  public listSessions(): ManagedSandboxSession[] {
    return [...this.sessions.values()];
  }

  public getSession(sessionId: string): ManagedSandboxSession | undefined {
    return this.sessions.get(sessionId);
  }

  public getWorkspacePath(sessionId: string): string | undefined {
    return this.workspacePaths.get(sessionId);
  }

  public async create(
    input: SandboxRouterInput = {},
    metadata?: Record<string, string>,
  ): Promise<ManagedSandboxSession> {
    const selection = await this.router.select(input);
    const now = new Date().toISOString();
    const baseSession = selection.backend.createSession
      ? await selection.backend.createSession(metadata)
      : {
          id: `${selection.backend.kind}-${randomUUID()}`,
          backend: selection.backend.kind,
          metadata,
        };

    const managedSession: ManagedSandboxSession = {
      ...baseSession,
      createdAt: now,
      lastUsedAt: now,
      persistent: Boolean(selection.backend.createSession),
    };

    this.sessions.set(managedSession.id, managedSession);
    this.sessionBackends.set(managedSession.id, selection.backend);

    if (this.workspaceDir) {
      const wsPath = join(this.workspaceDir, managedSession.id);
      await mkdir(wsPath, { recursive: true });
      this.workspacePaths.set(managedSession.id, wsPath);
    }

    return managedSession;
  }

  public async execute(
    sessionId: string,
    request: SandboxExecutionRequest,
  ): Promise<SandboxExecutionResult> {
    const { backend, session } = this.requireSession(sessionId);
    const result = await backend.execute(request, session);
    this.touch(sessionId);
    return result;
  }

  public async writeFiles(sessionId: string, files: SandboxFileEntry[]): Promise<void> {
    const { backend } = this.requireSession(sessionId);
    if (!backend.writeFiles) {
      throw new Error(`Sandbox backend '${backend.kind}' does not support file uploads`);
    }

    if (this.allowedWritePaths && this.allowedWritePaths.length > 0) {
      for (const file of files) {
        if (!isPathAllowed(file.path, this.allowedWritePaths)) {
          throw new Error(`Write to '${file.path}' is not permitted by the path whitelist`);
        }
      }
    }

    await backend.writeFiles(files, this.sessions.get(sessionId));
    this.touch(sessionId);
  }

  public async readFile(sessionId: string, path: string): Promise<string> {
    const { backend } = this.requireSession(sessionId);
    if (!backend.readFile) {
      throw new Error(`Sandbox backend '${backend.kind}' does not support file downloads`);
    }

    const content = await backend.readFile(path, this.sessions.get(sessionId));
    this.touch(sessionId);
    return content;
  }

  public async snapshot(sessionId: string): Promise<SandboxSnapshot> {
    const { backend, session } = this.requireSession(sessionId);
    if (!backend.snapshot) {
      throw new Error(`Sandbox backend '${backend.kind}' does not support snapshots`);
    }

    const snapshot = await backend.snapshot(session);
    this.touch(sessionId);
    return snapshot;
  }

  public async resume(snapshot: SandboxSnapshot): Promise<ManagedSandboxSession> {
    const backend = this.router.getBackend(snapshot.backend);
    if (!backend?.resume) {
      throw new Error(`Sandbox backend '${snapshot.backend}' does not support resume`);
    }

    const baseSession = await backend.resume(snapshot.id);
    const now = new Date().toISOString();
    const managedSession: ManagedSandboxSession = {
      ...baseSession,
      createdAt: now,
      lastUsedAt: now,
      persistent: true,
    };

    this.sessions.set(managedSession.id, managedSession);
    this.sessionBackends.set(managedSession.id, backend);
    return managedSession;
  }

  public async destroy(sessionId: string): Promise<void> {
    const { backend, session } = this.requireSession(sessionId);
    if (backend.destroySession) {
      await backend.destroySession(session.id);
    }

    this.sessions.delete(sessionId);
    this.sessionBackends.delete(sessionId);
    this.workspacePaths.delete(sessionId);
  }

  private requireSession(sessionId: string): {
    backend: SandboxBackend;
    session: SandboxSession;
  } {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Unknown sandbox session: ${sessionId}`);
    }

    const backend = this.sessionBackends.get(sessionId);
    if (!backend) {
      throw new Error(`Missing backend for sandbox session: ${sessionId}`);
    }

    return { backend, session };
  }

  private touch(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return;
    }

    session.lastUsedAt = new Date().toISOString();
  }
}
