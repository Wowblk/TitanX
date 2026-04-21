export type SandboxKind = "wasm" | "docker" | "e2b";

export type SandboxRiskLevel = "low" | "medium" | "high";

export type SandboxCapability =
  | "command-exec"
  | "filesystem"
  | "network"
  | "browser"
  | "package-install"
  | "snapshot"
  | "resume";

export interface SandboxExecutionRequest {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  input?: string;
}

export interface SandboxExecutionResult {
  backend: SandboxKind;
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
}

export interface SandboxFileEntry {
  path: string;
  content: string;
}

export interface SandboxSnapshot {
  id: string;
  createdAt: string;
  backend: SandboxKind;
}

export interface SandboxSession {
  id: string;
  backend: SandboxKind;
  metadata?: Record<string, string>;
}

export interface ManagedSandboxSession extends SandboxSession {
  createdAt: string;
  lastUsedAt: string;
  persistent: boolean;
}

export interface SandboxToolPolicy {
  preferredBackend?: SandboxKind;
  riskLevel?: SandboxRiskLevel;
  requiresRemoteIsolation?: boolean;
  needsFilesystem?: boolean;
  needsNetwork?: boolean;
  needsBrowser?: boolean;
  needsPackageInstall?: boolean;
}

export interface SandboxBackendCapabilities {
  kind: SandboxKind;
  supportsPersistence: boolean;
  supportsSnapshots: boolean;
  supportsBrowser: boolean;
  supportsNetwork: boolean;
  supportsPackageInstall: boolean;
  supportedCapabilities: SandboxCapability[];
}

export interface SandboxBackend {
  readonly kind: SandboxKind;
  capabilities(): SandboxBackendCapabilities;
  isAvailable(): Promise<boolean>;
  createSession?(metadata?: Record<string, string>): Promise<SandboxSession>;
  destroySession?(sessionId: string): Promise<void>;
  execute(
    request: SandboxExecutionRequest,
    session?: SandboxSession,
  ): Promise<SandboxExecutionResult>;
  writeFiles?(
    files: SandboxFileEntry[],
    session?: SandboxSession,
  ): Promise<void>;
  readFile?(path: string, session?: SandboxSession): Promise<string>;
  snapshot?(session: SandboxSession): Promise<SandboxSnapshot>;
  resume?(snapshotId: string): Promise<SandboxSession>;
}

export interface SandboxRouterInput {
  preferredBackend?: SandboxKind;
  riskLevel?: SandboxRiskLevel;
  requiresRemoteIsolation?: boolean;
  needsFilesystem?: boolean;
  needsNetwork?: boolean;
  needsBrowser?: boolean;
  needsPackageInstall?: boolean;
}

export interface SandboxSelection {
  backend: SandboxBackend;
  reason: string;
}

export interface RuntimeDirectories {
  logs: string;
  cache: string;
  workspace: string;
}
