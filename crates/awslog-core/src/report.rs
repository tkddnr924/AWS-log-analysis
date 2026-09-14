//! View models for the pre-parse screen (FR-4). Keeps core types out of the
//! IPC surface so the GUI contract can change independently.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;

use serde::Serialize;
use specta::Type;

use crate::detect::{Confidence, Detection, SampleRecord};
use crate::scan::{ScanReport, SkipReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum SkipKind {
    Extension,
    Empty,
    Unreadable,
}

#[derive(Debug, Clone, Serialize, Type)]
pub struct CandidateRow {
    pub display_path: String,
    #[specta(type = f64)]
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Type)]
pub struct SkippedRow {
    pub display_path: String,
    pub kind: SkipKind,
}

#[derive(Debug, Clone, Serialize, Type)]
pub struct ScanSummary {
    pub root: String,
    #[specta(type = u32)]
    pub candidate_count: usize,
    #[specta(type = f64)]
    pub total_bytes: u64,
    pub candidates: Vec<CandidateRow>,
    pub skipped: Vec<SkippedRow>,
}

#[derive(Debug, Clone, Serialize, Type)]
pub struct SampleRow {
    pub raw: Option<String>,
    pub event_time: Option<String>,
    pub event_source: Option<String>,
    pub event_name: Option<String>,
    pub aws_region: Option<String>,
    pub user_identity_type: Option<String>,
    pub user_identity_arn: Option<String>,
    pub source_ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Type)]
pub struct DetectionRow {
    pub display_path: String,
    pub log_type: String,
    pub confidence: String,
    #[specta(type = Option<u32>)]
    pub record_count_estimate: Option<u64>,
    pub estimated: bool,
    #[specta(type = u32)]
    pub members_in_head: usize,
    pub sample: Option<SampleRow>,
    pub note: Option<String>,
}

pub fn summarize_scan(report: &ScanReport) -> ScanSummary {
    let root = report.root.clone();
    ScanSummary {
        root: root.display().to_string(),
        candidate_count: report.candidates.len(),
        total_bytes: report.candidates.iter().map(|c| c.size_bytes).sum(),
        candidates: report
            .candidates
            .iter()
            .map(|c| CandidateRow {
                display_path: relative(&root, &c.path),
                size_bytes: c.size_bytes,
            })
            .collect(),
        skipped: report
            .skipped
            .iter()
            .map(|s| SkippedRow {
                display_path: relative(&root, &s.path),
                kind: match s.reason {
                    SkipReason::Extension => SkipKind::Extension,
                    SkipReason::Empty => SkipKind::Empty,
                    SkipReason::Unreadable => SkipKind::Unreadable,
                },
            })
            .collect(),
    }
}

pub fn to_row(root: &Path, detection: &Detection) -> DetectionRow {
    DetectionRow {
        display_path: relative(root, &detection.path),
        log_type: detection.log_type.as_str().to_owned(),
        confidence: confidence_name(detection.confidence).to_string(),
        record_count_estimate: detection.record_count_estimate,
        estimated: detection.estimated,
        members_in_head: detection.members_in_head,
        sample: detection.sample.as_ref().map(sample_row),
        note: detection.note.clone(),
    }
}

/// Detects every candidate in parallel and reports progress as it goes.
/// A file that cannot even be opened becomes an `unknown` row instead of
/// aborting the batch (NFR-4).
///
/// `on_progress` is called with the number of files finished so far; the
/// caller decides how often to forward that to the UI.
pub fn detect_all_with_progress(
    root: &Path,
    report: &ScanReport,
    on_progress: &(dyn Fn(usize, usize) + Sync),
) -> Vec<DetectionRow> {
    let total = report.candidates.len();
    let done = AtomicUsize::new(0);

    let mut rows: Vec<(usize, DetectionRow)> = report
        .candidates
        .par_iter()
        .enumerate()
        .map(|(index, candidate)| {
            let row = match crate::detect::detect_file(&candidate.path) {
                Ok(detection) => to_row(root, &detection),
                Err(err) => DetectionRow {
                    display_path: relative(root, &candidate.path),
                    log_type: "unknown".into(),
                    confidence: "none".into(),
                    record_count_estimate: None,
                    estimated: false,
                    members_in_head: 0,
                    sample: None,
                    note: Some(err.to_string()),
                },
            };
            on_progress(done.fetch_add(1, Ordering::Relaxed) + 1, total);
            (index, row)
        })
        .collect();

    // Parallel completion order is arbitrary; restore scan order for the UI.
    rows.sort_by_key(|(index, _)| *index);
    rows.into_iter().map(|(_, row)| row).collect()
}

/// Convenience wrapper for callers that do not track progress.
pub fn detect_all(root: &Path, report: &ScanReport) -> Vec<DetectionRow> {
    detect_all_with_progress(root, report, &|_, _| {})
}

fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "high",
        Confidence::Low => "low",
        Confidence::None => "none",
    }
}

fn sample_row(sample: &SampleRecord) -> SampleRow {
    SampleRow {
        raw: sample.raw.clone(),
        event_time: sample.event_time.clone(),
        event_source: sample.event_source.clone(),
        event_name: sample.event_name.clone(),
        aws_region: sample.aws_region.clone(),
        user_identity_type: sample.user_identity_type.clone(),
        user_identity_arn: sample.user_identity_arn.clone(),
        source_ip_address: sample.source_ip_address.clone(),
    }
}

/// Shortest path the UI can show: relative to the scanned root, forward slashes
/// so Windows and macOS render identically.
/// Path shown in the UI and used as the selection key. Always `/`-joined so
/// the same string round-trips from detection back into the parse request on
/// Windows, where `Path::display` would emit backslashes.
pub fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
