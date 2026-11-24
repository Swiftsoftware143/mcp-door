//! One audit line per call — who, what, how long, what happened.
//!
//! The record never carries a bearer token or a credential-shaped argument: arguments are truncated
//! and redacted before they are written. An audit that stores the key it audited is a second copy
//! of every secret, which is how a leak guard finds a fleet's keys in `/opt/swift/logs`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

/// One audited call. Serialized as a single JSON line.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// RFC 3339, UTC.
    pub ts: String,
    /// The door's server name, so one log file per app is still attributable when aggregated.
    pub door: String,
    /// Consumer name or key prefix — never the secret. `"-"` for an unauthenticated request.
    pub subject: String,
    pub role: String,
    pub tool: String,
    /// Truncated, redacted arguments.
    pub args: String,
    /// `ok`, `denied`, `unauthorized`, `tool_error: <code>`, `internal: <detail>`.
    pub outcome: String,
    /// Row count when the result carried `count`/`rows`/`total`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<u64>,
    pub duration_ms: u64,
}

impl AuditRecord {
    /// Build a record, redacting and truncating the arguments.
    pub fn new(
        door: &str,
        subject: &str,
        role: &str,
        tool: &str,
        args: &Value,
        outcome: &str,
        duration_ms: u64,
    ) -> Self {
        Self {
            ts: chrono::Utc::now().to_rfc3339(),
            door: door.to_string(),
            subject: subject.to_string(),
            role: role.to_string(),
            tool: tool.to_string(),
            args: render_args(args, 512),
            outcome: outcome.to_string(),
            rows: None,
            duration_ms,
        }
    }

    pub fn with_rows(mut self, rows: Option<u64>) -> Self {
        self.rows = rows;
        self
    }
}

/// Keys whose value must never reach the audit log, compared case-insensitively.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passphrase",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "private_key",
    "client_secret",
    "key_hash",
    "credential",
];

fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|s| k.contains(s))
}

/// Render arguments for the audit line: redact credential-shaped values, cap the length.
pub fn render_args(args: &Value, max_chars: usize) -> String {
    fn scrub(v: &Value, depth: usize) -> Value {
        if depth > 6 {
            return Value::String("[deep]".into());
        }
        match v {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, val)| {
                        if is_secret_key(k) {
                            (k.clone(), Value::String("[redacted]".into()))
                        } else {
                            (k.clone(), scrub(val, depth + 1))
                        }
                    })
                    .collect(),
            ),
            Value::Array(items) => {
                Value::Array(items.iter().map(|i| scrub(i, depth + 1)).collect())
            }
            Value::String(s) => {
                if s.len() > 200 {
                    Value::String(format!("{}…", s.chars().take(200).collect::<String>()))
                } else {
                    Value::String(s.clone())
                }
            }
            other => other.clone(),
        }
    }
    let text = scrub(args, 0).to_string();
    if text.chars().count() <= max_chars {
        text
    } else {
        format!("{}…", text.chars().take(max_chars).collect::<String>())
    }
}

/// Where audit lines go. Implement this to write into the app's own store instead of a file.
#[async_trait]
pub trait AuditSink: Send + Sync + 'static {
    async fn record(&self, record: &AuditRecord);
}

/// Append-only JSON-lines file, created `0600`.
///
/// Audit failures never fail the call: they print to stderr (where the service manager sees them)
/// and the request continues. Losing an audit line is bad; failing a customer's write because the
/// log disk is full is worse.
#[derive(Debug, Clone)]
pub struct FileAudit {
    path: PathBuf,
    /// Opened once, kept open, and written on a blocking thread. Keeping the handle (instead of
    /// open-per-line) makes the audit cheap under load and removes any doubt about ordering: the
    /// call's response is only built after the write has returned.
    file: Arc<Mutex<Option<std::fs::File>>>,
}

impl FileAudit {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            file: Arc::new(Mutex::new(None)),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl AuditSink for FileAudit {
    async fn record(&self, record: &AuditRecord) {
        let line = match serde_json::to_string(record) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[mcp-door] audit serialize failed: {e}");
                return;
            }
        };
        let path = self.path.clone();
        let slot = Arc::clone(&self.file);
        // A blocking write, awaited: audit is part of the call, not a background task that may
        // still be in flight when the caller (or its test) reads the file.
        let done = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            use std::io::Write;
            let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
            if guard.is_none() {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                let mut opts = std::fs::OpenOptions::new();
                opts.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                *guard = Some(opts.open(&path)?);
            }
            let file = guard.as_mut().expect("opened above");
            file.write_all(format!("{line}\n").as_bytes())?;
            file.flush()
        })
        .await;
        match done {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("[mcp-door] audit write {:?} failed: {e}", self.path),
            Err(e) => eprintln!("[mcp-door] audit task failed: {e}"),
        }
    }
}

/// Discards every record. For tests and for a door whose app writes its own audit.
#[derive(Debug, Default, Clone)]
pub struct NullAudit;

#[async_trait]
impl AuditSink for NullAudit {
    async fn record(&self, _record: &AuditRecord) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secrets_are_redacted_and_args_truncated() {
        let args = json!({
            "name": "Acme",
            "password": "hunter2",
            "nested": { "api_key": "sk_live_123", "ok": 1 },
            "list": ["a", {"token": "t"}],
        });
        let out = render_args(&args, 512);
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("sk_live_123"));
        assert!(!out.contains("\"t\""));
        assert!(out.contains("Acme"));
        assert!(out.contains("[redacted]"));
    }

    #[test]
    fn long_args_are_capped() {
        let args = json!({ "q": "x".repeat(5_000) });
        let out = render_args(&args, 512);
        assert!(out.chars().count() <= 513);
    }

    #[test]
    fn record_shape() {
        let r = AuditRecord::new(
            "coreswift",
            "csk_abc",
            "workspace",
            "list_contacts",
            &json!({}),
            "ok",
            12,
        )
        .with_rows(Some(3));
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.contains("\"rows\":3"));
        assert!(line.contains("\"tool\":\"list_contacts\""));
    }
}
