//! Run logs (FR-8). Every file lives under the cases root; nothing is written
//! to OS log directories. Log bodies never contain AWS event content — only
//! paths, counts and error kinds (AGENTS.md §4).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

use time::OffsetDateTime;

use crate::paths::{CaseDir, CasesRoot};

/// Longest error text kept in a log line. Parser errors can embed the offending
/// record, so they are truncated to the diagnostic prefix.
const MAX_REASON: usize = 80;

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn stamp() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn write_line(sink: &Mutex<File>, level: &str, message: &str) {
    let line = format!("{} {level} {message}\n", stamp());
    if let Ok(mut file) = sink.lock() {
        let _ = file.write_all(line.as_bytes());
    }
}

/// Application-wide log at `cases/app.log`.
pub struct AppLog {
    file: Mutex<File>,
}

impl AppLog {
    pub fn open(root: &CasesRoot) -> io::Result<Self> {
        Ok(Self {
            file: Mutex::new(open_append(&root.path().join("app.log"))?),
        })
    }

    pub fn info(&self, message: &str) {
        write_line(&self.file, "INFO", message);
    }

    pub fn error(&self, message: &str) {
        write_line(&self.file, "ERROR", message);
    }
}

/// Per-case logs: `logs/parse.log` for progress, `logs/warnings.log` for
/// skipped or damaged input (NFR-4).
pub struct CaseLog {
    parse: Mutex<File>,
    warnings: Mutex<File>,
}

impl CaseLog {
    pub fn open(case: &CaseDir) -> io::Result<Self> {
        let dir = case.logs_dir();
        Ok(Self {
            parse: Mutex::new(open_append(&dir.join("parse.log"))?),
            warnings: Mutex::new(open_append(&dir.join("warnings.log"))?),
        })
    }

    pub fn info(&self, message: &str) {
        write_line(&self.parse, "INFO", message);
    }

    /// Records where a record failed, never what it contained.
    pub fn warn_record_failure(&self, file: &Path, record_index: u64, reason: &str) {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.display().to_string());
        write_line(
            &self.warnings,
            "WARN",
            &format!("{name} record {record_index}: {}", redact(reason)),
        );
    }

    /// Records a file that was skipped entirely.
    pub fn warn_file_skipped(&self, file: &Path, reason: &str) {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.display().to_string());
        write_line(
            &self.warnings,
            "WARN",
            &format!("{name} skipped: {}", redact(reason)),
        );
    }
}

/// Keeps the diagnostic prefix and drops any embedded record payload.
/// Truncates at the first JSON/structure delimiter, then at a length cap.
pub(crate) fn redact(reason: &str) -> String {
    let mut cut = reason
        .find(['{', '[', '"'])
        .unwrap_or(reason.len())
        .min(MAX_REASON);
    // MAX_REASON counts bytes; back off to the nearest char boundary.
    while cut > 0 && !reason.is_char_boundary(cut) {
        cut -= 1;
    }
    let kept = reason[..cut].trim_end();
    if kept.len() < reason.trim_end().len() {
        format!("{kept} (details omitted)")
    } else {
        kept.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn redact_keeps_diagnostic_and_drops_payload() {
        assert_eq!(
            redact(r#"invalid type at {"arn":"arn:aws:iam::123456789012:user/alice"}"#),
            "invalid type at (details omitted)"
        );
    }

    #[test]
    fn redact_does_not_split_multibyte_characters() {
        // A long non-ASCII reason must truncate on a char boundary, not panic.
        let reason = "압축 해제 중 오류가 발생했습니다 ".repeat(8);
        let out = redact(&reason);
        assert!(reason.starts_with(&out.replace(" (details omitted)", "")));
    }

    #[test]
    fn redact_leaves_plain_reason_untouched() {
        assert_eq!(
            redact("unexpected end of gzip stream"),
            "unexpected end of gzip stream"
        );
    }
}
