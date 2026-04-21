import type {
  SandboxBackend,
  SandboxKind,
  SandboxRouterInput,
  SandboxSelection,
} from "./types.js";

export interface SandboxRouterOptions {
  defaultBackend?: SandboxKind;
}

export class SandboxRouter {
  private readonly backends = new Map<SandboxKind, SandboxBackend>();
  private readonly defaultBackend: SandboxKind;

  public constructor(backends: SandboxBackend[], options: SandboxRouterOptions = {}) {
    for (const backend of backends) {
      this.backends.set(backend.kind, backend);
    }
    this.defaultBackend = options.defaultBackend ?? "wasm";
  }

  public listBackends(): SandboxBackend[] {
    return [...this.backends.values()];
  }

  public getBackend(kind: SandboxKind): SandboxBackend | undefined {
    return this.backends.get(kind);
  }

  public async select(input: SandboxRouterInput = {}): Promise<SandboxSelection> {
    const candidates = this.rankCandidates(input);

    for (const candidate of candidates) {
      const backend = this.backends.get(candidate.kind);
      if (!backend) {
        continue;
      }
      if (await backend.isAvailable()) {
        return {
          backend,
          reason: candidate.reason,
        };
      }
    }

    throw new Error("No sandbox backend is available for the requested execution profile");
  }

  private rankCandidates(
    input: SandboxRouterInput,
  ): Array<{ kind: SandboxKind; reason: string }> {
    if (input.preferredBackend) {
      return [
        {
          kind: input.preferredBackend,
          reason: `preferred backend '${input.preferredBackend}' requested`,
        },
        ...this.fallbacksExcluding(input.preferredBackend),
      ];
    }

    if (input.requiresRemoteIsolation || input.riskLevel === "high" || input.needsBrowser) {
      return [
        { kind: "e2b", reason: "remote isolation selected for high-risk or browser workload" },
        { kind: "docker", reason: "docker fallback for isolated system workload" },
        { kind: "wasm", reason: "wasm fallback when stronger backends are unavailable" },
      ];
    }

    if (
      input.needsFilesystem ||
      input.needsNetwork ||
      input.needsPackageInstall ||
      input.riskLevel === "medium"
    ) {
      return [
        { kind: "docker", reason: "docker selected for filesystem, network, or package workload" },
        { kind: "e2b", reason: "e2b fallback for remotely isolated system workload" },
        { kind: "wasm", reason: "wasm fallback for reduced-capability execution" },
      ];
    }

    return [
      { kind: this.defaultBackend, reason: "default lightweight sandbox selected" },
      ...this.fallbacksExcluding(this.defaultBackend),
    ];
  }

  private fallbacksExcluding(kind: SandboxKind): Array<{ kind: SandboxKind; reason: string }> {
    return (["wasm", "docker", "e2b"] as SandboxKind[])
      .filter((candidate) => candidate !== kind)
      .map((candidate) => ({
        kind: candidate,
        reason: `fallback to '${candidate}' backend`,
      }));
  }
}
