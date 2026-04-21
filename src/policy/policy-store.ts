import { randomUUID } from "node:crypto";
import { AuditLog } from "./audit-log.js";
import type { AgentPolicy, PolicySnapshot, ReadonlyPolicyView } from "./types.js";

export class PolicyStore implements ReadonlyPolicyView {
  private current: AgentPolicy;
  private readonly snapshots: PolicySnapshot[] = [];

  public constructor(
    initial: AgentPolicy,
    private readonly auditLog: AuditLog = new AuditLog(),
  ) {
    this.current = { ...initial };
  }

  public getPolicy(): Readonly<AgentPolicy> {
    return this.current;
  }

  public getSnapshots(): ReadonlyArray<PolicySnapshot> {
    return this.snapshots;
  }

  public getAuditLog(): AuditLog {
    return this.auditLog;
  }

  public async set(
    policy: AgentPolicy,
    reason: string,
    actor: "host" | "system" = "host",
  ): Promise<PolicySnapshot> {
    const before = { ...this.current };
    const snapshot = this.saveSnapshot(reason);
    this.current = { ...policy };
    await this.auditLog.append({
      timestamp: new Date().toISOString(),
      event: "policy_change",
      actor,
      before,
      after: { ...this.current },
      reason,
      snapshotId: snapshot.id,
    });
    return snapshot;
  }

  public async rollback(snapshotId: string, actor: "host" | "system" = "host"): Promise<void> {
    const snapshot = this.snapshots.find((s) => s.id === snapshotId);
    if (!snapshot) throw new Error(`Unknown policy snapshot: ${snapshotId}`);
    const before = { ...this.current };
    this.current = { ...snapshot.policy };
    await this.auditLog.append({
      timestamp: new Date().toISOString(),
      event: "rollback",
      actor,
      before,
      after: { ...this.current },
      reason: `Rollback to snapshot ${snapshotId}: ${snapshot.reason}`,
      snapshotId,
    });
  }

  private saveSnapshot(reason: string): PolicySnapshot {
    const snapshot: PolicySnapshot = {
      id: randomUUID(),
      createdAt: new Date().toISOString(),
      policy: { ...this.current },
      reason,
    };
    this.snapshots.push(snapshot);
    return snapshot;
  }
}
