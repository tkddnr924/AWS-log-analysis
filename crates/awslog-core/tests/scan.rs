//! FR-2 directory scan (docs/03-log-detection.md step 1).

mod support;

use awslog_core::scan::{self, SkipReason};
use support::{gzip, write};

#[test]
fn collects_json_gz_recursively_through_cloudtrail_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(
        &root.join("AWSLogs/000000000000/CloudTrail/ap-northeast-2/2026/09/11/a.json.gz"),
        &gzip(b"{}"),
    );
    write(
        &root.join("AWSLogs/000000000000/CloudTrail/us-east-1/2026/09/11/b.json.gz"),
        &gzip(b"{}"),
    );

    let report = scan::scan_dir(root).unwrap();

    let mut names: Vec<_> = report
        .candidates
        .iter()
        .map(|c| c.path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["a.json.gz", "b.json.gz"]);
}

#[test]
fn collects_alb_log_gz_candidates_alongside_cloudtrail() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("trail.json.gz"), &gzip(b"{}"));
    write(&tmp.path().join("alb.log.gz"), &gzip(b"http sample"));
    write(&tmp.path().join("plain.log"), b"http sample");
    write(&tmp.path().join("waf.ndjson.gz"), &gzip(b"{}"));
    write(&tmp.path().join("EXPORT~1.GZ"), &gzip(b"http sample"));

    let report = scan::scan_dir(tmp.path()).unwrap();

    let names: Vec<_> = report
        .candidates
        .iter()
        .map(|candidate| {
            candidate
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        names,
        [
            "EXPORT~1.GZ",
            "alb.log.gz",
            "trail.json.gz",
            "waf.ndjson.gz"
        ]
    );
    assert_eq!(report.skipped.len(), 1);
    assert!(report.skipped[0].path.ends_with("plain.log"));
}

#[test]
fn reports_non_matching_extensions_as_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("a.json.gz"), &gzip(b"{}"));
    write(&tmp.path().join("notes.txt"), b"hello");
    write(&tmp.path().join("digest.json"), b"{}");

    let report = scan::scan_dir(tmp.path()).unwrap();

    assert_eq!(report.candidates.len(), 1);
    let skipped: Vec<_> = report
        .skipped
        .iter()
        .map(|s| {
            (
                s.path.file_name().unwrap().to_string_lossy().into_owned(),
                s.reason,
            )
        })
        .collect();
    assert!(skipped.contains(&("notes.txt".into(), SkipReason::Extension)));
    assert!(skipped.contains(&("digest.json".into(), SkipReason::Extension)));
}

#[test]
fn empty_file_is_skipped_not_offered_as_candidate() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("empty.json.gz"), b"");

    let report = scan::scan_dir(tmp.path()).unwrap();

    assert!(report.candidates.is_empty());
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].reason, SkipReason::Empty);
}

#[test]
fn candidate_carries_size_for_progress_estimation() {
    let tmp = tempfile::tempdir().unwrap();
    let bytes = gzip(b"{\"Records\":[]}");
    write(&tmp.path().join("a.json.gz"), &bytes);

    let report = scan::scan_dir(tmp.path()).unwrap();

    assert_eq!(report.candidates[0].size_bytes, bytes.len() as u64);
}

#[cfg(unix)]
#[test]
fn symlink_loop_does_not_hang_the_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(&root.join("deep/a.json.gz"), &gzip(b"{}"));
    // deep/loop -> deep : following it would recurse forever.
    std::os::unix::fs::symlink(root.join("deep"), root.join("deep/loop")).unwrap();

    let report = scan::scan_dir(root).unwrap();

    assert_eq!(report.candidates.len(), 1);
}

#[cfg(unix)]
#[test]
fn symlinked_file_is_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(&root.join("real/a.json.gz"), &gzip(b"{}"));
    std::os::unix::fs::symlink(root.join("real/a.json.gz"), root.join("link.json.gz")).unwrap();

    let report = scan::scan_dir(root).unwrap();

    assert_eq!(report.candidates.len(), 1);
    assert!(report.candidates[0].path.ends_with("real/a.json.gz"));
}

#[test]
fn missing_directory_is_an_error_not_an_empty_report() {
    let err = scan::scan_dir(std::path::Path::new("/no/such/dir")).unwrap_err();
    assert!(err.to_string().contains("/no/such/dir"));
}

#[test]
fn candidates_are_sorted_so_the_ui_list_is_reproducible() {
    let tmp = tempfile::tempdir().unwrap();
    for name in ["c.json.gz", "a.json.gz", "b.json.gz"] {
        write(&tmp.path().join(name), &gzip(b"{}"));
    }

    let report = scan::scan_dir(tmp.path()).unwrap();

    let names: Vec<_> = report
        .candidates
        .iter()
        .map(|c| c.path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["a.json.gz", "b.json.gz", "c.json.gz"]);
}

#[test]
fn os_metadata_files_are_ignored_not_reported_as_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join(".DS_Store"), b"junk");
    write(&tmp.path().join("sub/.DS_Store"), b"junk");
    write(&tmp.path().join("Thumbs.db"), b"junk");
    // Windows exports arrive with inconsistent casing.
    write(&tmp.path().join("DESKTOP.INI"), b"junk");
    // AppleDouble sidecar: ends with .json.gz, so it would pass the
    // extension check and be parsed as a log if metadata were tested second.
    write(&tmp.path().join("._log.json.gz"), b"junk");
    write(&tmp.path().join("notes.txt"), b"hello");

    let report = scan::scan_dir(tmp.path()).unwrap();

    // Desktop metadata is noise the analyst never chose to put there; only
    // files they might have expected to be parsed belong in the report.
    let listed: Vec<_> = report
        .skipped
        .iter()
        .map(|s| s.path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(listed, vec!["notes.txt"]);
    assert!(report.candidates.is_empty());
}
