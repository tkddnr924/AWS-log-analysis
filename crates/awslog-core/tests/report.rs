//! FR-4 pre-parse summary shown in the GUI.

mod support;

use awslog_core::report::{self, SkipKind};
use awslog_core::{detect, scan};
use support::{cloudtrail_json, cloudtrail_record, gzip, write};

#[test]
fn scan_summary_counts_candidates_and_groups_skip_reasons() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("a.json.gz"), &gzip(b"{}"));
    write(&tmp.path().join("b.json.gz"), &gzip(b"{}"));
    write(&tmp.path().join("notes.txt"), b"x");
    write(&tmp.path().join("empty.json.gz"), b"");

    let summary = report::summarize_scan(&scan::scan_dir(tmp.path()).unwrap());

    assert_eq!(summary.candidate_count, 2);
    assert_eq!(summary.total_bytes, 2 * summary.candidates[0].size_bytes);
    let kinds: Vec<_> = summary.skipped.iter().map(|s| s.kind).collect();
    assert!(kinds.contains(&SkipKind::Extension));
    assert!(kinds.contains(&SkipKind::Empty));
}

#[test]
fn candidate_exposes_a_path_relative_to_the_scanned_root() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        &tmp.path().join("AWSLogs/acct/CloudTrail/x.json.gz"),
        &gzip(b"{}"),
    );

    let scanned = scan::scan_dir(tmp.path()).unwrap();
    let summary = report::summarize_scan(&scanned);

    // Absolute paths are long and leak the analyst's directory layout in
    // screenshots; the UI shows the path relative to the chosen root.
    assert_eq!(
        summary.candidates[0].display_path,
        "AWSLogs/acct/CloudTrail/x.json.gz"
    );
}

#[test]
fn detection_row_carries_type_confidence_and_sample_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("a.json.gz");
    let json = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    write(&path, &gzip(json.as_bytes()));

    let row = report::to_row(tmp.path(), &detect::detect_file(&path).unwrap());

    assert_eq!(row.log_type, "cloudtrail");
    assert_eq!(row.confidence, "high");
    assert_eq!(row.display_path, "a.json.gz");
    let sample = row.sample.expect("sample record");
    assert_eq!(sample.event_name.as_deref(), Some("ConsoleLogin"));
    assert!(row.note.is_none());
}

#[test]
fn undetected_file_row_keeps_the_reason_for_the_user() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("broken.json.gz");
    write(&path, b"definitely not gzip");

    let row = report::to_row(tmp.path(), &detect::detect_file(&path).unwrap());

    assert_eq!(row.log_type, "unknown");
    assert!(row.sample.is_none());
    assert!(row.note.unwrap().contains("gzip"));
}

#[test]
fn detect_all_isolates_a_damaged_file_and_keeps_the_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let good = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    write(&tmp.path().join("good.json.gz"), &gzip(good.as_bytes()));
    write(&tmp.path().join("bad.json.gz"), b"garbage");

    let scanned = scan::scan_dir(tmp.path()).unwrap();
    let rows = report::detect_all(tmp.path(), &scanned);

    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter().filter(|r| r.log_type == "cloudtrail").count(),
        1
    );
    assert_eq!(rows.iter().filter(|r| r.log_type == "unknown").count(), 1);
}
