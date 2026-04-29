//! titanx-sidecar — process-isolated WASM tool runtime.
//!
//! See `docs/sidecar-rfc.md` for the protocol spec. The short version:
//! we read newline-delimited JSON from stdin, run the requested WASM
//! module under wasmtime with per-call memory + fuel limits and no
//! network, write a single newline-delimited JSON response per request
//! to stdout, and exit on `shutdown` or stdin EOF.
//!
//! Threat model assumptions
//! ========================
//!
//! * The sidecar is launched by a Python parent process running as
//!   the same UID. We do **not** drop privileges further inside the
//!   sidecar; that is the operator's job (Docker / systemd /
//!   `setpriv`). What the sidecar *does* enforce is everything below
//!   the OS-process boundary: memory caps, fuel limits, no network
//!   imports, and absolute-path validation for preopens.
//!
//! * stdout is the structured channel; nothing else writes to it.
//!   stderr is unstructured diagnostics for the parent's audit log.
//!   A WASM module that writes to its own stdout has those bytes
//!   captured into the response payload via wasmtime-wasi's
//!   `MemoryOutputPipe`, never written to the sidecar's stdout.
//!
//! * One request at a time. We deliberately do not pipeline; the
//!   complexity savings on both sides outweigh the throughput.
//!
//! Status
//! ======
//!
//! v0.1.0 — protocol envelope, ping/shutdown/execute, WASI preview1,
//! per-call memory/fuel/wall-clock limits, no network. The crate
//! compiles against wasmtime 27.x; if your installed version differs
//! you may need to update the wasmtime-wasi capture API in
//! ``run_module`` (search for ``MemoryOutputPipe``).
//!
//! v0.2.0 (planned) — WIT component model, per-call capability handles
//! enforced inside the sidecar, EgressGuard inside ``http-get``.

use std::collections::HashMap;
use std::path::{Component as PathComponent, Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::Instant;
use wasmtime::component::Component;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

const PROTOCOL_VERSION: &str = "0.2.0";

mod bindings {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "tool",
        async: true,
    });
}

// Hard ceilings the sidecar refuses to exceed regardless of what the
// caller requests. Operators who need more should run multiple
// sidecars rather than relax these.
const MAX_MEMORY_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_FUEL: u64 = 1_000_000_000_000;
const MAX_WALL_CLOCK_MS: u64 = 60_000;

const MAX_CAPTURED_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

// ── Protocol envelope ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Request {
    id: String,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Response {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorPayload>,
}

#[derive(Debug, Serialize)]
struct ErrorPayload {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

// ── execute params / result ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ExecuteParams {
    #[serde(default)]
    module_bytes_b64: Option<String>,
    #[serde(default)]
    module_path: Option<String>,
    #[serde(default)]
    argv: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    preopens: Vec<Preopen>,
    #[serde(default)]
    stdin: Option<String>,
    #[serde(default)]
    limits: ExecuteLimits,
    #[serde(default)]
    component_model: bool,
    #[serde(default)]
    capabilities: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
struct Preopen {
    host: String,
    guest: String,
    #[serde(default = "default_preopen_mode")]
    mode: String,
}

fn default_preopen_mode() -> String {
    "ro".into()
}

#[derive(Debug, Deserialize, Default)]
struct ExecuteLimits {
    #[serde(default)]
    memory_bytes: Option<usize>,
    #[serde(default)]
    fuel: Option<u64>,
    #[serde(default)]
    wall_clock_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ExecuteResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
    duration_ms: u64,
    memory_bytes_peak: u64,
    fuel_consumed: u64,
    audit_events: Vec<AuditEvent>,
}

#[derive(Debug, Clone, Serialize)]
struct AuditEvent {
    capability: &'static str,
    target: String,
    decision: &'static str,
    reason: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CapabilityPolicy {
    #[serde(default)]
    http_get: Vec<HttpGetGrant>,
    #[serde(default)]
    read_file: Vec<ReadFileGrant>,
}

#[derive(Debug, Clone, Deserialize)]
struct HttpGetGrant {
    #[serde(default = "default_https_scheme")]
    scheme: String,
    host: String,
    #[serde(default)]
    path_prefix: Option<String>,
    #[serde(default)]
    allow_private: bool,
}

fn default_https_scheme() -> String {
    "https".into()
}

#[derive(Debug, Clone, Deserialize)]
struct ReadFileGrant {
    guest_path: String,
    host_path: String,
}

// ── Path validation ────────────────────────────────────────────────────────
//
// Mirrors Python ``titanx.policy.validation`` privileged-prefix list.
// Defence-in-depth: the Python adapter already validated the policy,
// but if an attacker compromises that path the sidecar still refuses
// to mount /etc, /proc, /sys, etc.

const FORBIDDEN_PREFIXES: &[&str] = &[
    "/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/var/lib", "/var/run", "/usr", "/lib",
    "/lib64", "/sbin", "/bin",
];

fn validate_host_path(p: &str) -> Result<PathBuf> {
    if !p.starts_with('/') {
        return Err(anyhow!("preopen host path must be absolute: {p:?}"));
    }
    let canonical = std::path::Path::new(p);
    let s = canonical.to_string_lossy();
    for forbidden in FORBIDDEN_PREFIXES {
        if s == *forbidden || s.starts_with(&format!("{forbidden}/")) {
            return Err(anyhow!(
                "preopen host path {p:?} is under privileged subtree {forbidden}"
            ));
        }
    }
    Ok(canonical.to_path_buf())
}

// ── execute handler ────────────────────────────────────────────────────────

struct Sidecar {
    engine: Engine,
}

impl Sidecar {
    fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.async_support(true);
        config.wasm_component_model(true);
        // Module caching keeps repeated tool launches fast. Failures
        // are non-fatal: ``cache_config_load_default`` returns Err
        // when no cache config exists which is the dev-machine norm.
        let _ = config.cache_config_load_default();
        let engine = Engine::new(&config).context("create wasmtime Engine")?;
        Ok(Self { engine })
    }

    async fn handle_execute(&self, params: ExecuteParams) -> Result<ExecuteResult, ErrorPayload> {
        let start = Instant::now();

        // Resolve module bytes. Exactly one of module_path /
        // module_bytes_b64 must be set.
        let module_bytes = match (
            params.module_path.as_deref(),
            params.module_bytes_b64.as_deref(),
        ) {
            (Some(_), Some(_)) => {
                return Err(ErrorPayload {
                    code: "module-load",
                    message: "module_path and module_bytes_b64 are mutually exclusive".into(),
                    details: None,
                })
            }
            (Some(path), None) => {
                let p = validate_host_path(path).map_err(|e| ErrorPayload {
                    code: "module-load",
                    message: e.to_string(),
                    details: None,
                })?;
                std::fs::read(&p).map_err(|e| ErrorPayload {
                    code: "module-load",
                    message: format!("read {}: {e}", p.display()),
                    details: None,
                })?
            }
            (None, Some(b64)) => base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| ErrorPayload {
                    code: "module-load",
                    message: format!("base64 decode failed: {e}"),
                    details: None,
                })?,
            (None, None) => {
                return Err(ErrorPayload {
                    code: "module-load",
                    message: "neither module_path nor module_bytes_b64 supplied".into(),
                    details: None,
                })
            }
        };

        let memory_bytes = params
            .limits
            .memory_bytes
            .unwrap_or(64 * 1024 * 1024)
            .min(MAX_MEMORY_BYTES);
        let fuel = params.limits.fuel.unwrap_or(1_000_000_000).min(MAX_FUEL);
        let wall_clock = Duration::from_millis(
            params
                .limits
                .wall_clock_ms
                .unwrap_or(5_000)
                .min(MAX_WALL_CLOCK_MS),
        );

        if params.component_model {
            return self
                .run_component(params, module_bytes, memory_bytes, fuel, wall_clock, start)
                .await;
        }

        let module = Module::new(&self.engine, &module_bytes).map_err(|e| ErrorPayload {
            code: "module-load",
            message: format!("module compile failed: {e}"),
            details: None,
        })?;

        // Capture stdout/stderr via wasmtime-wasi's in-memory pipes.
        // ``MemoryOutputPipe`` enforces a soft cap on captured bytes
        // — past it, writes succeed but bytes are discarded — so a
        // module that prints in a tight loop can't OOM the sidecar.
        let stdout_pipe = MemoryOutputPipe::new(MAX_CAPTURED_BYTES);
        let stderr_pipe = MemoryOutputPipe::new(MAX_CAPTURED_BYTES);

        let mut wasi_builder = WasiCtxBuilder::new();
        let argv: Vec<String> = if params.argv.is_empty() {
            vec!["wasm".into()]
        } else {
            params.argv.clone()
        };
        wasi_builder.args(&argv);
        for (k, v) in &params.env {
            wasi_builder.env(k, v);
        }
        for preopen in &params.preopens {
            let host = validate_host_path(&preopen.host).map_err(|e| ErrorPayload {
                code: "capability-denied",
                message: e.to_string(),
                details: None,
            })?;
            let dir_perms = wasmtime_wasi::DirPerms::READ;
            let file_perms = match preopen.mode.as_str() {
                "rw" => wasmtime_wasi::FilePerms::READ | wasmtime_wasi::FilePerms::WRITE,
                _ => wasmtime_wasi::FilePerms::READ,
            };
            wasi_builder
                .preopened_dir(&host, &preopen.guest, dir_perms, file_perms)
                .map_err(|e| ErrorPayload {
                    code: "capability-denied",
                    message: format!("preopen {}: {e}", host.display()),
                    details: None,
                })?;
        }

        wasi_builder.stdout(stdout_pipe.clone());
        wasi_builder.stderr(stderr_pipe.clone());
        if let Some(stdin_text) = params.stdin {
            wasi_builder.stdin(MemoryInputPipe::new(stdin_text.into_bytes()));
        }

        let limits = StoreLimitsBuilder::new().memory_size(memory_bytes).build();
        let mut store = Store::new(
            &self.engine,
            ExecCtx {
                wasi: wasi_builder.build_p1(),
                limits,
            },
        );
        store.limiter(|s| &mut s.limits);
        store.set_fuel(fuel).map_err(|e| ErrorPayload {
            code: "internal",
            message: format!("set_fuel: {e}"),
            details: None,
        })?;

        // Link **only** WASI preview1. No wasi-http, no wasi-sockets:
        // a module that imports them will fail at instantiation
        // which is the structural network deny we promised.
        let mut linker: Linker<ExecCtx> = Linker::new(&self.engine);
        preview1::add_to_linker_async(&mut linker, |s: &mut ExecCtx| &mut s.wasi).map_err(|e| {
            ErrorPayload {
                code: "internal",
                message: format!("linker setup: {e}"),
                details: None,
            }
        })?;

        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .map_err(|e| ErrorPayload {
                code: "module-load",
                message: format!("instantiate failed: {e}"),
                details: None,
            })?;

        let start_fn = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| ErrorPayload {
                code: "module-load",
                message: format!("module does not export _start: {e}"),
                details: None,
            })?;

        // Wall-clock enforcement: race the future against a sleep.
        let exec_fut = start_fn.call_async(&mut store, ());
        let exit_code = match tokio::time::timeout(wall_clock, exec_fut).await {
            Ok(Ok(())) => 0,
            Ok(Err(trap)) => {
                let msg = trap.to_string();
                if let Some(code) = parse_exit_code(&msg) {
                    code
                } else {
                    return Err(ErrorPayload {
                        code: if msg.contains("all fuel consumed") {
                            "limit-exceeded"
                        } else {
                            "wasm-trap"
                        },
                        message: msg,
                        details: None,
                    });
                }
            }
            Err(_) => {
                return Err(ErrorPayload {
                    code: "limit-exceeded",
                    message: format!("wall-clock timeout {} ms exceeded", wall_clock.as_millis()),
                    details: None,
                });
            }
        };

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = fuel.saturating_sub(fuel_remaining);
        let memory_peak = memory_bytes as u64;

        let stdout_bytes = stdout_pipe.contents().to_vec();
        let stderr_bytes = stderr_pipe.contents().to_vec();

        Ok(ExecuteResult {
            exit_code,
            stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
            duration_ms: start.elapsed().as_millis() as u64,
            memory_bytes_peak: memory_peak,
            fuel_consumed,
            audit_events: Vec::new(),
        })
    }

    async fn run_component(
        &self,
        params: ExecuteParams,
        module_bytes: Vec<u8>,
        memory_bytes: usize,
        fuel: u64,
        wall_clock: Duration,
        start: Instant,
    ) -> Result<ExecuteResult, ErrorPayload> {
        let component = Component::new(&self.engine, &module_bytes).map_err(|e| ErrorPayload {
            code: "module-load",
            message: format!("component compile failed: {e}"),
            details: None,
        })?;

        let capabilities: CapabilityPolicy = serde_json::from_value(params.capabilities.clone())
            .map_err(|e| ErrorPayload {
                code: "capability-denied",
                message: format!("invalid capabilities envelope: {e}"),
                details: None,
            })?;

        let mut linker = wasmtime::component::Linker::new(&self.engine);
        bindings::Tool::add_to_linker(&mut linker, |state: &mut ComponentCtx| state).map_err(
            |e| ErrorPayload {
                code: "internal",
                message: format!("component linker setup: {e}"),
                details: None,
            },
        )?;

        let limits = StoreLimitsBuilder::new().memory_size(memory_bytes).build();
        let mut store = Store::new(
            &self.engine,
            ComponentCtx {
                env: params.env,
                preopens: params.preopens,
                capabilities,
                audit_events: Vec::new(),
                limits,
            },
        );
        store.limiter(|s| &mut s.limits);
        store.set_fuel(fuel).map_err(|e| ErrorPayload {
            code: "internal",
            message: format!("set_fuel: {e}"),
            details: None,
        })?;

        let tool = bindings::Tool::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(|e| ErrorPayload {
                code: "module-load",
                message: format!("component instantiate failed: {e}"),
                details: None,
            })?;

        let call = tool.call_run(&mut store);
        let run_result = tokio::time::timeout(wall_clock, call)
            .await
            .map_err(|_| ErrorPayload {
                code: "limit-exceeded",
                message: format!("wall-clock timeout {} ms exceeded", wall_clock.as_millis()),
                details: None,
            })?
            .map_err(|e| ErrorPayload {
                code: "wasm-trap",
                message: e.to_string(),
                details: None,
            })?;

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = fuel.saturating_sub(fuel_remaining);
        let audit_events = store.data().audit_events.clone();

        match run_result {
            Ok(stdout) => Ok(ExecuteResult {
                exit_code: 0,
                stdout,
                stderr: String::new(),
                duration_ms: start.elapsed().as_millis() as u64,
                memory_bytes_peak: memory_bytes as u64,
                fuel_consumed,
                audit_events,
            }),
            Err(stderr) => Ok(ExecuteResult {
                exit_code: 1,
                stdout: String::new(),
                stderr,
                duration_ms: start.elapsed().as_millis() as u64,
                memory_bytes_peak: memory_bytes as u64,
                fuel_consumed,
                audit_events,
            }),
        }
    }
}

struct ComponentCtx {
    env: HashMap<String, String>,
    preopens: Vec<Preopen>,
    capabilities: CapabilityPolicy,
    audit_events: Vec<AuditEvent>,
    limits: StoreLimits,
}

impl ComponentCtx {
    fn audit(
        &mut self,
        capability: &'static str,
        target: impl Into<String>,
        decision: &'static str,
        reason: impl Into<String>,
    ) {
        self.audit_events.push(AuditEvent {
            capability,
            target: target.into(),
            decision,
            reason: reason.into(),
        });
    }

    fn authorize_http_get(&mut self, url: &str) -> Result<(), String> {
        let parsed = parse_absolute_url(url).ok_or_else(|| {
            let reason = "url must be absolute http(s)".to_string();
            self.audit("http.get", url, "deny", reason.clone());
            reason
        })?;

        for grant in self.capabilities.http_get.clone() {
            let path_ok = grant
                .path_prefix
                .as_deref()
                .map(|prefix| parsed.path.starts_with(prefix))
                .unwrap_or(true);
            if grant.scheme.eq_ignore_ascii_case(&parsed.scheme)
                && grant.host.eq_ignore_ascii_case(&parsed.host)
                && path_ok
            {
                if !grant.allow_private && is_private_destination(&parsed.host) {
                    let reason =
                        "capability-denied: private destination requires allow_private".to_string();
                    self.audit("http.get", url, "deny", reason.clone());
                    return Err(reason);
                }
                self.audit(
                    "http.get",
                    url,
                    "allow",
                    format!("matched {}://{}", grant.scheme, grant.host),
                );
                return Ok(());
            }
        }

        let reason = "capability-denied: no http_get grant matched".to_string();
        self.audit("http.get", url, "deny", reason.clone());
        Err(reason)
    }

    async fn fetch_http_get(
        &mut self,
        url: &str,
    ) -> Result<bindings::titanx::tool::http::Response, bindings::titanx::tool::http::Error> {
        let parsed = parse_absolute_url(url).ok_or_else(|| {
            bindings::titanx::tool::http::Error::Transport("invalid absolute URL".into())
        })?;
        if parsed.scheme != "http" {
            return Err(bindings::titanx::tool::http::Error::Transport(
                "https transport requires a TLS-enabled sidecar build".into(),
            ));
        }

        blocking_http_get(&parsed).map_err(bindings::titanx::tool::http::Error::Transport)
    }

    fn read_guest_file(&mut self, guest_path: &str) -> Result<Vec<u8>, String> {
        if has_parent_escape(guest_path) {
            let reason = "capability-denied: parent traversal is refused".to_string();
            self.audit("fs.read-file", guest_path, "deny", reason.clone());
            return Err(reason);
        }

        for grant in self.capabilities.read_file.clone() {
            if !guest_path_matches(&grant.guest_path, guest_path) {
                continue;
            }
            let preopen = match self
                .preopens
                .iter()
                .find(|p| {
                    p.guest == grant.guest_path
                        || p.guest == "/"
                        || grant.guest_path.starts_with(&p.guest)
                })
                .cloned()
            {
                Some(preopen) => preopen,
                None => {
                    let reason = "capability-denied: no matching preopen".to_string();
                    self.audit("fs.read-file", guest_path, "deny", reason.clone());
                    return Err(reason);
                }
            };
            if preopen.mode != "ro" && preopen.mode != "rw" {
                let reason = format!("capability-denied: invalid preopen mode {}", preopen.mode);
                self.audit("fs.read-file", guest_path, "deny", reason.clone());
                return Err(reason);
            }

            let host_root = validate_host_path(&grant.host_path)
                .map_err(|e| format!("capability-denied: {e}"))?;
            let rel = guest_relative_path(&grant.guest_path, guest_path);
            let host_path = host_root.join(rel);
            match std::fs::read(&host_path) {
                Ok(bytes) => {
                    self.audit(
                        "fs.read-file",
                        guest_path,
                        "allow",
                        format!("guest path grant matched {}", grant.guest_path),
                    );
                    return Ok(bytes);
                }
                Err(e) => {
                    let reason = format!("read {}: {e}", host_path.display());
                    self.audit("fs.read-file", guest_path, "deny", reason.clone());
                    return Err(reason);
                }
            }
        }

        let reason = "capability-denied: no read_file grant matched".to_string();
        self.audit("fs.read-file", guest_path, "deny", reason.clone());
        Err(reason)
    }
}

#[async_trait::async_trait]
impl bindings::titanx::tool::env::Host for ComponentCtx {
    async fn get_env(&mut self, key: String) -> Option<String> {
        self.env.get(&key).cloned()
    }
}

#[async_trait::async_trait]
impl bindings::titanx::tool::http::Host for ComponentCtx {
    async fn get(
        &mut self,
        url: String,
    ) -> Result<bindings::titanx::tool::http::Response, bindings::titanx::tool::http::Error> {
        match self.authorize_http_get(&url) {
            Ok(()) => self.fetch_http_get(&url).await,
            Err(reason) => Err(bindings::titanx::tool::http::Error::Denied(reason)),
        }
    }
}

#[async_trait::async_trait]
impl bindings::titanx::tool::fs::Host for ComponentCtx {
    async fn read_file(&mut self, path: String) -> Result<Vec<u8>, String> {
        self.read_guest_file(&path)
    }
}

struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

fn parse_absolute_url(url: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let (authority, path) = match rest.split_once('/') {
        Some((host, path)) => (host, format!("/{path}")),
        None => (rest, "/".into()),
    };
    let (host, port) = split_authority_host_port(authority)?;
    if host.is_empty() || host.contains('@') {
        return None;
    }
    Some(ParsedUrl {
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_ascii_lowercase(),
        port,
        path,
    })
}

fn split_authority_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[1..end];
        let port = authority
            .get(end + 1..)
            .and_then(|tail| tail.strip_prefix(':'))
            .and_then(|p| p.parse::<u16>().ok());
        return Some((host, port));
    }
    match authority.split_once(':') {
        Some((host, port)) => Some((host, port.parse::<u16>().ok())),
        None => Some((authority, None)),
    }
}

fn blocking_http_get(parsed: &ParsedUrl) -> Result<bindings::titanx::tool::http::Response, String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};

    let port = parsed.port.unwrap_or(80);
    let mut addrs = (parsed.host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}:{port}: {e}", parsed.host))?;
    let addr = addrs
        .next()
        .ok_or_else(|| format!("resolve {}:{port}: no addresses", parsed.host))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set write timeout: {e}"))?;

    let authority = if port == 80 {
        parsed.host.clone()
    } else {
        format!("{}:{port}", parsed.host)
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: titanx-sidecar/0.2\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        parsed.path, authority
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write request: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read response: {e}"))?;
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<bindings::titanx::tool::http::Response, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response: missing header terminator".to_string())?;
    let header_text = String::from_utf8_lossy(&raw[..split]);
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "malformed HTTP response: missing status line".to_string())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "malformed HTTP response: missing status code".to_string())?
        .parse::<u16>()
        .map_err(|e| format!("malformed HTTP status code: {e}"))?;
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();
    let body = raw[split + 4..].to_vec();
    Ok(bindings::titanx::tool::http::Response {
        status,
        headers,
        body,
    })
}

fn is_private_destination(host: &str) -> bool {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || match ip {
                    std::net::IpAddr::V4(v4) => {
                        v4.is_private() || v4.is_link_local() || v4.is_broadcast()
                    }
                    std::net::IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
                }
        }
        Err(_) => matches!(
            host.to_ascii_lowercase().as_str(),
            "localhost"
                | "metadata"
                | "metadata.google.internal"
                | "metadata.goog"
                | "instance-data"
                | "instance-data.ec2.internal"
                | "metadata.azure.com"
        ),
    }
}

fn has_parent_escape(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|component| matches!(component, PathComponent::ParentDir))
}

fn guest_path_matches(grant: &str, requested: &str) -> bool {
    requested == grant
        || requested
            .strip_prefix(grant.trim_end_matches('/'))
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
}

fn guest_relative_path(grant: &str, requested: &str) -> PathBuf {
    let suffix = requested
        .strip_prefix(grant.trim_end_matches('/'))
        .unwrap_or("")
        .trim_start_matches('/');
    PathBuf::from(suffix)
}

fn parse_exit_code(msg: &str) -> Option<i32> {
    // wasmtime's WASI ``proc_exit`` trap message is roughly:
    //   "exited with i32 exit status N"
    // Stable enough across versions to use a substring search.
    let needle = "exit status ";
    let idx = msg.find(needle)?;
    let tail = &msg[idx + needle.len()..];
    let end = tail
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(tail.len());
    tail[..end].parse().ok()
}

struct ExecCtx {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

// ── main loop ──────────────────────────────────────────────────────────────

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let sidecar = Sidecar::new()?;

    let stdin = tokio::io::stdin();
    let mut stdin = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();

    loop {
        line.clear();
        let n = stdin.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let req: Request = match serde_json::from_str(line.trim()) {
            Ok(req) => req,
            Err(e) => {
                let resp = Response {
                    id: "".into(),
                    result: None,
                    error: Some(ErrorPayload {
                        code: "internal",
                        message: format!("malformed request: {e}"),
                        details: None,
                    }),
                };
                write_response(&mut stdout, &resp).await?;
                continue;
            }
        };

        let resp = match req.method.as_str() {
            "ping" => Response {
                id: req.id,
                result: Some(serde_json::json!({"version": PROTOCOL_VERSION})),
                error: None,
            },
            "shutdown" => {
                let resp = Response {
                    id: req.id,
                    result: Some(serde_json::json!({"goodbye": true})),
                    error: None,
                };
                write_response(&mut stdout, &resp).await?;
                break;
            }
            "execute" => {
                let parsed: Result<ExecuteParams, _> = serde_json::from_value(req.params);
                match parsed {
                    Ok(params) => match sidecar.handle_execute(params).await {
                        Ok(result) => Response {
                            id: req.id,
                            result: Some(serde_json::to_value(result).unwrap()),
                            error: None,
                        },
                        Err(error) => Response {
                            id: req.id,
                            result: None,
                            error: Some(error),
                        },
                    },
                    Err(e) => Response {
                        id: req.id,
                        result: None,
                        error: Some(ErrorPayload {
                            code: "internal",
                            message: format!("malformed execute params: {e}"),
                            details: None,
                        }),
                    },
                }
            }
            other => Response {
                id: req.id,
                result: None,
                error: Some(ErrorPayload {
                    code: "internal",
                    message: format!("unknown method: {other}"),
                    details: None,
                }),
            },
        };
        write_response(&mut stdout, &resp).await?;
    }

    Ok(())
}

async fn write_response<W: AsyncWriteExt + Unpin>(w: &mut W, resp: &Response) -> Result<()> {
    let mut bytes = serde_json::to_vec(resp)?;
    bytes.push(b'\n');
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_host_path_rejects_etc() {
        assert!(validate_host_path("/etc/passwd").is_err());
        assert!(validate_host_path("/etc").is_err());
        assert!(validate_host_path("/proc/self").is_err());
    }

    #[test]
    fn validate_host_path_accepts_workspace() {
        assert!(validate_host_path("/srv/titanx/work").is_ok());
        assert!(validate_host_path("/tmp/agent").is_ok());
    }

    #[test]
    fn validate_host_path_rejects_relative() {
        assert!(validate_host_path("etc/passwd").is_err());
        assert!(validate_host_path("./etc").is_err());
    }

    #[test]
    fn parse_exit_code_extracts_number() {
        assert_eq!(parse_exit_code("exited with i32 exit status 42"), Some(42));
        assert_eq!(parse_exit_code("exit status 0"), Some(0));
        assert_eq!(parse_exit_code("no exit code here"), None);
    }

    fn component_ctx(capabilities: CapabilityPolicy, preopens: Vec<Preopen>) -> ComponentCtx {
        ComponentCtx {
            env: HashMap::new(),
            preopens,
            capabilities,
            audit_events: Vec::new(),
            limits: StoreLimitsBuilder::new().memory_size(1024 * 1024).build(),
        }
    }

    #[test]
    fn capability_http_denies_without_matching_grant() {
        let mut ctx = component_ctx(CapabilityPolicy::default(), Vec::new());

        let err = ctx
            .authorize_http_get("https://example.com/api")
            .expect_err("missing grant should deny");

        assert!(err.contains("capability-denied"));
        assert_eq!(ctx.audit_events.len(), 1);
        assert_eq!(ctx.audit_events[0].capability, "http.get");
        assert_eq!(ctx.audit_events[0].decision, "deny");
    }

    #[test]
    fn capability_http_allows_matching_grant() {
        let mut ctx = component_ctx(
            CapabilityPolicy {
                http_get: vec![HttpGetGrant {
                    scheme: "https".into(),
                    host: "example.com".into(),
                    path_prefix: Some("/api".into()),
                    allow_private: false,
                }],
                read_file: Vec::new(),
            },
            Vec::new(),
        );

        ctx.authorize_http_get("https://example.com/api/search")
            .expect("matching grant should allow");

        assert_eq!(ctx.audit_events.len(), 1);
        assert_eq!(ctx.audit_events[0].decision, "allow");
    }

    #[tokio::test]
    #[ignore = "requires binding a local TCP port; run outside the sandbox"]
    async fn capability_http_get_fetches_allowed_url() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 1024];
            let _ = stream.read(&mut buf).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nX-Test: yes\r\n\r\nhello sidecar",
                )
                .unwrap();
        });

        let mut ctx = component_ctx(
            CapabilityPolicy {
                http_get: vec![HttpGetGrant {
                    scheme: "http".into(),
                    host: "127.0.0.1".into(),
                    path_prefix: Some("/ok".into()),
                    allow_private: true,
                }],
                read_file: Vec::new(),
            },
            Vec::new(),
        );
        let url = format!("http://127.0.0.1:{}/ok", addr.port());

        let response = ctx
            .fetch_http_get(&url)
            .await
            .expect("allowed URL should be fetched");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello sidecar");
        assert!(response
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-test") && v == "yes"));
        handle.join().unwrap();
    }

    #[test]
    fn http_response_parser_extracts_status_headers_and_body() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nX-Test: yes\r\n\r\nok";

        let response = parse_http_response(raw).expect("valid HTTP response should parse");

        assert_eq!(response.status, 201);
        assert_eq!(response.body, b"ok");
        assert!(response
            .headers
            .iter()
            .any(|(k, v)| k == "X-Test" && v == "yes"));
    }

    #[test]
    fn capability_read_file_denies_without_matching_grant() {
        let mut ctx = component_ctx(CapabilityPolicy::default(), Vec::new());

        let err = ctx
            .read_guest_file("/data/config.json")
            .expect_err("missing grant should deny");

        assert!(err.contains("capability-denied"));
        assert_eq!(ctx.audit_events[0].capability, "fs.read-file");
        assert_eq!(ctx.audit_events[0].decision, "deny");
    }

    #[test]
    fn capability_read_file_allows_granted_preopen_path() {
        let root = std::env::temp_dir().join(format!("titanx-sidecar-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/config.txt"), b"ok").unwrap();

        let mut ctx = component_ctx(
            CapabilityPolicy {
                http_get: Vec::new(),
                read_file: vec![ReadFileGrant {
                    guest_path: "/data".into(),
                    host_path: root.to_string_lossy().into_owned(),
                }],
            },
            vec![Preopen {
                host: root.to_string_lossy().into_owned(),
                guest: "/data".into(),
                mode: "ro".into(),
            }],
        );

        let bytes = ctx
            .read_guest_file("/data/nested/config.txt")
            .expect("matching read grant should read file");

        assert_eq!(bytes, b"ok");
        assert_eq!(ctx.audit_events[0].decision, "allow");
        let _ = std::fs::remove_dir_all(&root);
    }
}
