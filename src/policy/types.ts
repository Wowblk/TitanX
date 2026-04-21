export interface AgentPolicy {
  allowedWritePaths: string[];
  autoApproveTools: boolean;
  maxIterations: number;
}

export interface PolicySnapshot {
  id: string;
  createdAt: string;
  policy: AgentPolicy;
  reason: string;
}

export interface AuditEntry {
  timestamp: string;
  event: "policy_change" | "break_glass_activated" | "break_glass_expired" | "rollback";
  actor: "host" | "system";
  before: AgentPolicy;
  after: AgentPolicy;
  reason: string;
  snapshotId?: string;
}

export interface BreakGlassSession {
  activatedAt: string;
  expiresAt: string;
  originalSnapshotId: string;
}

// Agent-facing read-only view — no write access to policy or audit log.
export interface ReadonlyPolicyView {
  getPolicy(): Readonly<AgentPolicy>;
}
