//! FR-2: collect supported gzip candidates without reading their contents.
//! Content is not read here — detection happens in `detect`.

use std::io;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Any gzip file is a candidate: exports arrive as `.json.gz`, `.log.gz`,
/// `.ndjson.gz` and occasionally a bare `.GZ`. What it holds is decided by
/// content in `detect`, never by the name.
const CANDIDATE_SUFFIX: &str = ".gz";

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("cannot read input directory: {path} ({source})")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Not a supported gzip log filename.
    Extension,
    /// Zero bytes; nothing to decode.
    Empty,
    /// Metadata could not be read.
    Unreadable,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: PathBuf,
    pub size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Skipped {
    pub path: PathBuf,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    /// Directory the user chose; display paths are relative to it.
    pub root: PathBuf,
    pub candidates: Vec<Candidate>,
    pub skipped: Vec<Skipped>,
}

/// Walks `root` recursively. Symlinks are not followed: a link back to an
/// ancestor would loop forever, and a linked file would be analysed twice.
pub fn scan_dir(root: &Path) -> Result<ScanReport, ScanError> {
    let meta = std::fs::metadata(root).map_err(|source| ScanError::Unreadable {
        path: root.to_path_buf(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(ScanError::Unreadable {
            path: root.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "not a directory"),
        });
    }

    let mut report = ScanReport {
        root: root.to_path_buf(),
        ..Default::default()
    };

    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                if let Some(path) = err.path() {
                    report.skipped.push(Skipped {
                        path: path.to_path_buf(),
                        reason: SkipReason::Unreadable,
                    });
                }
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();

        // Desktop metadata the user never put there: not a candidate, and
        // not worth reporting as an exclusion either.
        if is_os_metadata(path) {
            continue;
        }

        if !is_candidate_name(path) {
            report.skipped.push(Skipped {
                path: path.to_path_buf(),
                reason: SkipReason::Extension,
            });
            continue;
        }

        match entry.metadata() {
            Ok(meta) if meta.len() == 0 => report.skipped.push(Skipped {
                path: path.to_path_buf(),
                reason: SkipReason::Empty,
            }),
            Ok(meta) => report.candidates.push(Candidate {
                path: path.to_path_buf(),
                size_bytes: meta.len(),
            }),
            Err(_) => report.skipped.push(Skipped {
                path: path.to_path_buf(),
                reason: SkipReason::Unreadable,
            }),
        }
    }

    // Directory order is filesystem-dependent; sort so the UI list and any
    // later parse run are reproducible.
    report.candidates.sort_by(|a, b| a.path.cmp(&b.path));
    report.skipped.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(report)
}

/// Files created by the OS or file manager, never by the log export.
fn is_os_metadata(path: &Path) -> bool {
    const NAMES: [&str; 4] = [".ds_store", "thumbs.db", "desktop.ini", ".localized"];
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        let lower = n.to_ascii_lowercase();
        NAMES.contains(&lower.as_str()) || lower.starts_with("._")
    })
}

fn is_candidate_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().ends_with(CANDIDATE_SUFFIX))
}
