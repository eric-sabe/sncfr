use crate::error::SncfrError;
use chrono::Utc;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

static VERBOSE_STDERR: AtomicBool = AtomicBool::new(false);
static LOG_FILE_ENABLED: AtomicBool = AtomicBool::new(false);
static LOG_FILE: OnceLock<Mutex<Option<File>>> = OnceLock::new();

/// Initializes diagnostic logging for the current `sncfr` invocation.
///
/// - When `verbose_stderr` is `true` (`-v` / `--verbose` / `SNCFR_VERBOSE=1`), timestamped debug lines are emitted to `stderr`.
/// - When `log_file` is `Some(path)` (`--log-file` / `SNCFR_LOG_FILE`), timestamped debug lines are appended to `path`.
pub fn init(verbose_stderr: bool, log_file: Option<&Path>) -> Result<(), SncfrError> {
    VERBOSE_STDERR.store(verbose_stderr, Ordering::SeqCst);

    if let Some(path) = log_file {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| SncfrError::InvalidArgs {
                message: format!(
                    "Failed to create parent directory for log file '{}': {e}",
                    path.display()
                ),
                remediation: None,
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| SncfrError::InvalidArgs {
                message: format!("Failed to open debug log file '{}': {e}", path.display()),
                remediation: None,
            })?;
        let mutex = LOG_FILE.get_or_init(|| Mutex::new(None));
        if let Ok(mut guard) = mutex.lock() {
            *guard = Some(file);
        }
        LOG_FILE_ENABLED.store(true, Ordering::SeqCst);
    }

    if is_enabled() {
        emit(
            "init",
            &format!(
                "sncfr v{} initialized (os={}, arch={}, stderr_verbose={}, log_file={})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH,
                verbose_stderr,
                log_file.map_or_else(|| "none".to_string(), |p| p.display().to_string())
            ),
        );
    }

    Ok(())
}

/// Returns `true` if either `-v`/`--verbose` or `--log-file` is active.
#[inline]
pub fn is_enabled() -> bool {
    VERBOSE_STDERR.load(Ordering::Relaxed) || LOG_FILE_ENABLED.load(Ordering::Relaxed)
}

/// Emits a formatted diagnostic log line to `stderr` and/or the configured `--log-file`.
pub fn emit(target: &str, message: &str) {
    if !is_enabled() {
        return;
    }
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let line = format!("[{ts} DEBUG {target}] {message}");

    if VERBOSE_STDERR.load(Ordering::Relaxed) {
        eprintln!("{line}");
    }

    if LOG_FILE_ENABLED.load(Ordering::Relaxed)
        && let Some(mutex) = LOG_FILE.get()
        && let Ok(mut guard) = mutex.lock()
        && let Some(file) = guard.as_mut()
    {
        let _ = writeln!(file, "{line}");
        let _ = file.flush();
    }
}

/// Redacts a secret token while preserving diagnostic metadata (length and first 6 characters).
pub fn redact_token(token: Option<&str>) -> String {
    let Some(raw) = token.map(str::trim).filter(|s| !s.is_empty()) else {
        return "missing".to_string();
    };
    let len = raw.len();
    let prefix: String = raw.chars().take(6).collect();
    if len > 8 {
        format!("present (len={len}, prefix={prefix}...)")
    } else {
        format!("present (len={len})")
    }
}

/// Summarizes a `Cookie` header by listing only the cookie names (never the secret cookie values).
pub fn summarize_cookie_names(cookie_header: &str) -> String {
    let names: Vec<&str> = cookie_header
        .split(';')
        .filter_map(|pair| {
            let trimmed = pair.trim();
            if trimmed.is_empty() {
                return None;
            }
            trimmed.split_once('=').map(|(k, _)| k.trim())
        })
        .collect();
    format!("{} cookies [{}]", names.len(), names.join(", "))
}

/// Emits a formatted debug log entry when `-v` / `--verbose` or `--log-file` is active.
#[macro_export]
macro_rules! debug_log {
    ($target:expr, $($arg:tt)*) => {
        if $crate::log::is_enabled() {
            $crate::log::emit($target, &format!($($arg)*));
        }
    };
}
