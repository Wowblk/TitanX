import { PolicyStore } from "./policy-store.js";
import type { AgentPolicy, BreakGlassSession } from "./types.js";

export class BreakGlassController {
  private activeSession: BreakGlassSession | null = null;
  private timer: NodeJS.Timeout | null = null;

  public constructor(private readonly store: PolicyStore) {}

  public isActive(): boolean {
    return this.activeSession !== null;
  }

  public getSession(): Readonly<BreakGlassSession> | null {
    return this.activeSession;
  }

  public async activate(
    reason: string,
    ttlMs: number,
    relaxedPolicy: AgentPolicy,
  ): Promise<BreakGlassSession> {
    if (this.activeSession) {
      throw new Error("A break-glass session is already active");
    }

    const before = { ...this.store.getPolicy() };
    const snapshot = await this.store.set(relaxedPolicy, `break_glass: ${reason}`, "host");

    const now = Date.now();
    const session: BreakGlassSession = {
      activatedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlMs).toISOString(),
      originalSnapshotId: snapshot.id,
    };
    this.activeSession = session;

    await this.store.getAuditLog().append({
      timestamp: new Date(now).toISOString(),
      event: "break_glass_activated",
      actor: "host",
      before,
      after: relaxedPolicy,
      reason,
      snapshotId: snapshot.id,
    });

    this.timer = setTimeout(() => void this.expire(), ttlMs);
    return session;
  }

  public dispose(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  private async expire(): Promise<void> {
    if (!this.activeSession) return;
    const session = this.activeSession;
    this.activeSession = null;
    this.timer = null;

    const before = { ...this.store.getPolicy() };
    await this.store.rollback(session.originalSnapshotId, "system");

    await this.store.getAuditLog().append({
      timestamp: new Date().toISOString(),
      event: "break_glass_expired",
      actor: "system",
      before,
      after: { ...this.store.getPolicy() },
      reason: "TTL expired — policy auto-restored",
      snapshotId: session.originalSnapshotId,
    });
  }
}
