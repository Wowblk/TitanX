# TitanX Security Model

This document is the **authoritative** statement of TitanX's threat model,
trust boundaries, and out-of-scope assumptions. If a behaviour you observed
isn't in scope here, it is intentional, and we will respond to a report by
linking back to this file.

If you believe you have found a vulnerability that **is** in scope, please
follow the disclosure instructions at the bottom of this file before
opening a public issue.

---

## 1. What TitanX is, and what it isn't

TitanX is a **single-tenant Agent SDK**. Its security posture is designed
around the same trust model as a personal assistant: one operator, one
runtime instance, one set of policies.

The primary trust boundary is between:

| Side               | Treatment                              |
| ------------------ | -------------------------------------- |
| **Operator**       | Fully trusted (configures `AgentPolicy`, runs the host process). |
| **Host process**   | Fully trusted (constructs the runtime, embeds an `LlmAdapter`). |
| **LLM output**     | **Untrusted**, even when the LLM is internal. Re-checked by `SafetyLayer` and gated by `PolicyStore`. |
| **Tool output / RAG content** | **Untrusted**. Treated as adversarial data — `SafetyLayer.inspect_tool_output` runs an injection scan on every tool result. |
| **End-user prompt** | **Untrusted**, but lower-risk than tool/LLM output. `SafetyLayer.check_input` applies first. |

TitanX is **not** a multi-tenant access-control system. It does not enforce
isolation between two end-users sharing the same gateway, and a successful
policy change applies to every concurrent session. Hosts that need
multi-tenant separation must run one runtime per tenant.

## 2. Defenses in scope

These are the layers TitanX is willing to be measured against. A bypass
that defeats one of these without operator complicity is in scope.

1. **Input validation & PII redaction** (`titanx/safety/`).
   `SafetyLayer.check_input` runs Unicode NFKC normalisation, multi-language
   injection-pattern matching, and PII redaction on every prompt before
   the runtime sees it.
2. **Indirect-injection scan on tool output** (`SafetyLayer.inspect_tool_output`).
   Always-on. Tool output is wrapped in `<tool_output>…</tool_output>`
   structural markers when `AgentConfig.wrap_tool_output=True`.
3. **PolicyStore validation** (`titanx/policy/validation.py`).
   `validate_policy` rejects any `AgentPolicy` that would let the Docker
   sandbox bind-mount a privileged path (`/`, `/etc`, `/proc`, `/var/run`,
   `/var/lib/docker`, etc.). The same forbidden list applies to
   `allowed_read_paths` — read-only mounts of host config / state are
   still leaks, so they are blocked at the same boundary. Defense-in-depth:
   the Docker backend re-validates the same paths at the kernel-mount
   boundary.
3a. **OCI image-digest pin** (`AgentPolicy.image_digest`,
    `DockerSandboxBackendOptions.expected_image_digest`,
    `ImageDigestMismatch`).
    When set, `DockerSandboxBackend` resolves the configured image
    via `docker inspect` (or an injected resolver) before launch and
    refuses to start on mismatch. A `repo@sha256:` reference embedded
    in the image string short-circuits the inspect (Docker enforces
    the match itself). Sessions are verified at creation time so a
    long-lived container cannot survive a registry compromise.
3b. **Read / write mount split** (`AgentPolicy.allowed_read_paths`).
    Host paths can be exposed `:ro` without granting writability,
    matching NemoClaw's `filesystem_policy.read_only`. Backends without
    a mount surface (wasm) ignore the list; the audit module flags
    overlap between `allowed_read_paths` and `allowed_write_paths`.
4. **Sandbox isolation floor** (`SandboxRouter.select(min_isolation=…)`).
   When a tool requires a minimum isolation tier and no available backend
   meets it, `select` raises rather than silently downgrading.
5. **Approval gate** (`PolicyStore.check_tool` + `requires_approval`).
   Each LLM-issued tool call is independently checked. The runtime
   buffers the entire batch when an approval pause is required so no
   `tool_call.id` is ever orphaned in the message log.
6. **Cancellation contract** (`AgentRuntime.run_prompt` cancellation path).
   When the host cancels the task mid-tool-execution the runtime
   synthesises a `ToolMessage` for the in-flight call, sets
   `state.signal="interrupt"`, emits `LoopEndEvent(reason="cancelled")`,
   and re-raises `CancelledError`. The OpenAI/Anthropic tool-call
   protocol invariant survives the interrupt.
7. **Break-glass lifecycle** (`BreakGlassController`).
   Activations have a TTL, are audited, and roll back the *original*
   policy. Manual `revoke()` and TTL expiry are mutually exclusive.
8. **Append-only audit log** (`AuditLog` JSONL).
   Schema-versioned, fsync-policy configurable, with a single writer
   coroutine to prevent line-interleaving. Optional `secondary_sink`
   fan-out to relational storage; failures disable the sink without
   affecting the durable JSONL record.
9. **Outbound HTTP allowlist** (`titanx/safety/egress.py`, new in 0.2.x).
   Hosts that issue HTTP from inside tools route through `EgressGuard`,
   which enforces `IronClawWasmToolSpec.http_allowlist` against the
   actual destination host, port, scheme, and path. Default action is
   **deny**.
9a. **Per-tool egress scoping** (`OutboundRule.caller`,
    `EgressGuard.from_ironclaw_specs(scope_to_caller=True)`,
    `caller_scope`).
    A rule may pin to a specific tool / handler identity; the guard
    fail-closed when the caller is missing or differs, so a privileged
    egress rule cannot be inherited by generic code paths. The runtime
    binds the dispatched tool's name as the ambient caller around every
    `tools.execute(...)` via the `contextvars`-backed `caller_scope`,
    so handler code that omits `caller=` still gets correctly scoped
    decisions. The bundled `titanx.safety.presets` (`slack`, `github`,
    `discord`, `google`, `huggingface`, `pypi`, `npm_registry`,
    `brave_search`, `composio`, `telegram`) ship caller-scoped
    allowlists out of the box.
10. **Bounded session map** (`SessionRegistry`).
    LRU + idle-TTL caps the in-memory session dict; an unauthenticated WS
    client cannot pin memory.
11. **Constant-time API-key comparison** in the gateway HTTP middleware
    *and* WebSocket handshake.

## 3. Out of scope (and why)

These are deliberate non-goals. A report against any of these is treated
as a feature request, not a vulnerability.

- **Multi-tenant isolation**. TitanX assumes one operator. Two end-users
  on the same runtime can see each other's policy snapshots and the
  same audit log.
- **Defending against the operator**. An operator who installs a
  malicious `LlmAdapter`, hands the runtime a tool whose handler reads
  `/etc/shadow`, or sets `auto_approve_tools=True` on a relaxed policy
  is acting from inside the trust boundary. We document the foot-guns
  (`titanx security audit`) but do not enforce policy *on the operator*.
- **Defending against a malicious LLM provider**. If the LLM provider is
  exfiltrating prompts or returning crafted tool calls designed to
  abuse a specific tool, TitanX layers (Safety, PolicyStore, Sandbox)
  raise the cost but do not eliminate the threat. Operators with
  high-sensitivity workloads should run a local model.
- **Side channels in the host kernel / Docker / wasmtime / e2b**.
  We rely on the underlying isolation primitive. CVEs in those layers
  are reportable upstream, not to us.
- **DNS rebinding against `EgressGuard`**. The guard verifies the host
  string at request time. A rebinding attack that re-resolves the host
  between TitanX's check and the actual `connect(2)` is the host's
  HTTP client's responsibility (pin the IP after resolution, or use a
  pinning HTTP library).
- **Memory disclosure in unrelated Python libraries**. Not our scope.
- **Rate-limiting / DoS on the LLM provider**. The runtime caps per-prompt
  iterations (`max_iterations`) and total runtime via `RetryOptions.max_total_time_ms`,
  but it is not a rate-limiting proxy.
- **Secret-in-source-code leaks**. Use a real secrets manager. The
  audit-log redactor is best-effort, not a vault.

## 4. Researcher preflight

Before opening a report, please run:

```bash
python -m titanx.cli audit --policy /path/to/your/policy.json \
                           --audit-log /path/to/audit.jsonl \
                           --gateway /path/to/gateway.json
```

A clean `audit` output (no `critical` findings) is a precondition for
most reports. If the audit catches your finding, the configuration is
the bug — fix it and re-run TitanX.

If the audit is clean and the issue is reproducible, please attach:

1. The exact `AgentPolicy` (JSON form is fine).
2. The `GatewayOptions` if the gateway is involved.
3. A minimal `LlmAdapter` that reproduces the behaviour.
4. The TitanX version (`pip show titanx`) and Python version.

## 5. Disclosure

Send reports to `security@<your-domain>` (replace with the project's
contact). For now, please do **not** open public GitHub issues for
unfixed vulnerabilities; pre-disclosure coordination is preferred.

We aim to acknowledge within 5 business days and ship a fix within 30
days for in-scope reports of `critical` or `high` severity.
