//! Session store: schema, batch load, case metadata (docs/05-data-model.md).

mod support;

use awslog_core::model::NormalizedEvent;
use awslog_core::store::{CaseStatus, Store, StoreError};
use std::sync::atomic::{AtomicU64, Ordering};
use time::macros::datetime;

fn event(index: u64, name: &str) -> NormalizedEvent {
    NormalizedEvent {
        file_id: 1,
        record_index: index,
        event_time: Some(datetime!(2026-09-11 02:03:04).assume_utc()),
        event_source: Some("signin.amazonaws.com".into()),
        event_name: Some(name.into()),
        aws_region: Some("ap-northeast-2".into()),
        account_id: Some("000000000000".into()),
        source_ip: Some("203.0.113.10".into()),
        user_agent: None,
        identity_type: Some("IAMUser".into()),
        identity_arn: Some("arn:aws:iam::000000000000:user/masked".into()),
        identity_name: Some("masked".into()),
        mfa_authenticated: Some(false),
        error_code: None,
        error_message: None,
        read_only: Some(false),
        management_event: Some(true),
        request: None,
        response: Some(r#"{"ConsoleLogin":"Failure"}"#.into()),
        resources: None,
        raw: Some(r#"{"eventName":"ConsoleLogin"}"#.into()),
    }
}

#[test]
fn creates_schema_and_reports_zero_events_for_a_new_case() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::create(&tmp.path().join("session.duckdb"), "case-1", "/logs").unwrap();

    assert_eq!(store.event_count(&Default::default()).unwrap(), 0);
    assert_eq!(store.case_status().unwrap(), CaseStatus::Running);
}

#[test]
fn appends_events_in_batches_and_counts_them() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "case-1", "/logs").unwrap();

    store
        .register_file(1, "a.json.gz", 1234, "cloudtrail")
        .unwrap();
    let batch: Vec<_> = (0..5_000).map(|i| event(i, "ConsoleLogin")).collect();
    store.append_events(&batch).unwrap();

    assert_eq!(store.event_count(&Default::default()).unwrap(), 5_000);
}

#[test]
fn a_cancelled_scan_stops_at_the_row_the_cancel_lands_on() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "case-1", "/logs").unwrap();
    store
        .register_file(1, "a.json.gz", 1234, "cloudtrail")
        .unwrap();
    let batch: Vec<_> = (0..5).map(|i| event(i, "ConsoleLogin")).collect();
    store.append_events(&batch).unwrap();
    let seen = AtomicU64::new(0);

    let err = store
        .scan_events(
            None,
            |_| true,
            |_, _, _| {
                seen.fetch_add(1, Ordering::Relaxed);
            },
            || seen.load(Ordering::Relaxed) >= 2,
        )
        .unwrap_err();

    // Stopping only at the end of the file would keep a cancelled run
    // reading the whole case.
    assert!(matches!(err, StoreError::Cancelled));
    assert_eq!(seen.load(Ordering::Relaxed), 2);
}

#[test]
fn a_file_with_a_gap_is_scanned_past_the_chunk_boundary() {
    // Malformed records leave holes in `record_index`: the parser numbers
    // every line and stores only the ones that normalize. A scan that reads
    // 50,000-row ranges and stops as soon as a range comes back short would
    // end the file at its first hole and silently drop the rest.
    const LAST: u64 = 60_000;
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "case-1", "/logs").unwrap();
    store
        .register_file(1, "a.json.gz", 1234, "cloudtrail")
        .unwrap();
    let batch: Vec<_> = (0..=LAST)
        .filter(|index| *index != 10)
        .map(|index| event(index, "ConsoleLogin"))
        .collect();
    store.append_events(&batch).unwrap();

    let mut seen = 0u64;
    store.for_each_typed_event(|_, _, _| seen += 1).unwrap();

    assert_eq!(seen, LAST);
}

// getrusage is unix-only; the invariant is platform-independent so measuring
// it on one platform is enough. The high-water mark is process-wide, so each
// probe runs in a child process of its own: sibling tests would otherwise
// raise or mask it.

#[cfg(unix)]
#[test]
fn scanning_events_for_rules_does_not_hold_the_table_in_memory() {
    // The rule pass reads every event back. It must stream: a materialized
    // result set once put 31M rows of JSON in memory at once (NFR-2).
    // Tripling the rows (spread over files, as a real case is) must not
    // raise the process high-water mark in step.
    let small = scan_and_measure(3, 20_000);
    let large = scan_and_measure(9, 20_000);

    assert!(
        large <= small.max(1) * 2,
        "peak growth scaled with event count: {small} -> {large} bytes for 3x rows"
    );
}

#[cfg(unix)]
#[test]
fn scanning_one_large_file_is_bounded_by_the_chunk_not_the_file() {
    // scan must chunk inside a file too. Both sizes exceed one chunk.
    let small = scan_and_measure(1, 120_000);
    let large = scan_and_measure(1, 360_000);

    assert!(
        large <= small.max(1) * 2,
        "peak growth scaled with file size: {small} -> {large} bytes for 3x rows"
    );
}

/// Peak RSS growth in bytes while scanning `files` × `per_file` fat events,
/// measured by `rss_probe` in a fresh test process.
#[cfg(unix)]
fn scan_and_measure(files: u32, per_file: u64) -> u64 {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "rss_probe", "--ignored", "--nocapture"])
        .env("AWSLOG_RSS_PROBE", format!("{files},{per_file}"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("growth=")?.parse().ok())
        .unwrap_or_else(|| panic!("probe produced no growth line:\n{stdout}"))
}

/// Child side of `scan_and_measure`; not a test on its own.
#[cfg(unix)]
#[test]
#[ignore]
fn rss_probe() {
    let Ok(spec) = std::env::var("AWSLOG_RSS_PROBE") else {
        return;
    };
    let (files, per_file) = spec.split_once(',').unwrap();
    let (files, per_file): (u32, u64) = (files.parse().unwrap(), per_file.parse().unwrap());
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "case-1", "/logs").unwrap();
    let raw = format!(
        r#"{{"eventName":"ConsoleLogin","pad":"{}"}}"#,
        "x".repeat(400)
    );
    for file_id in 0..files {
        store
            .register_file(file_id, &format!("{file_id}.json.gz"), 1, "cloudtrail")
            .unwrap();
        // Appended in parser-sized batches so the fixture itself stays small.
        for start in (0..per_file).step_by(10_000) {
            let batch: Vec<_> = (start..(start + 10_000).min(per_file))
                .map(|i| {
                    let mut e = event(i, "ConsoleLogin");
                    e.file_id = file_id;
                    e.raw = Some(raw.clone());
                    e
                })
                .collect();
            store.append_events(&batch).unwrap();
        }
    }

    let before = peak_rss();
    let mut seen = 0u64;
    store.for_each_typed_event(|_, _, _| seen += 1).unwrap();
    assert_eq!(seen, u64::from(files) * per_file);
    println!("growth={}", peak_rss().saturating_sub(before));
}

#[cfg(target_os = "macos")]
fn peak_rss() -> u64 {
    // ru_maxrss is bytes on macOS.
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage.ru_maxrss as u64
    }
}

#[cfg(target_os = "linux")]
fn peak_rss() -> u64 {
    // ru_maxrss is kilobytes on Linux.
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage.ru_maxrss as u64 * 1024
    }
}

#[test]
fn stored_event_keeps_every_normalized_field() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "case-1", "/logs").unwrap();
    store
        .register_file(1, "a.json.gz", 1, "cloudtrail")
        .unwrap();

    store.append_events(&[event(7, "AssumeRole")]).unwrap();

    let row = store.first_event().unwrap().expect("one event");
    assert_eq!(row.record_index, 7);
    assert_eq!(row.event_name.as_deref(), Some("AssumeRole"));
    assert_eq!(
        row.identity_arn.as_deref(),
        Some("arn:aws:iam::000000000000:user/masked")
    );
    assert_eq!(row.mfa_authenticated, Some(false));
    // `raw` is the rule engine's escape hatch; it must survive the round trip.
    assert!(row.raw.unwrap().contains("ConsoleLogin"));
}

#[test]
fn finishing_a_case_records_status_and_end_time() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::create(&tmp.path().join("s.duckdb"), "case-1", "/logs").unwrap();

    store.finish(CaseStatus::Done).unwrap();

    assert_eq!(store.case_status().unwrap(), CaseStatus::Done);
    assert!(store.finished_at().unwrap().is_some());
}

#[test]
fn cancelled_case_keeps_the_events_already_written() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("s.duckdb");
    let mut store = Store::create(&path, "case-1", "/logs").unwrap();
    store
        .register_file(1, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    store.append_events(&[event(0, "ConsoleLogin")]).unwrap();

    store.finish(CaseStatus::Cancelled).unwrap();
    drop(store);

    // Reopening proves the partial result is durable, not just in memory.
    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.case_status().unwrap(), CaseStatus::Cancelled);
    assert_eq!(reopened.event_count(&Default::default()).unwrap(), 1);
}

#[test]
fn case_meta_is_the_source_for_regenerating_case_json() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::create(&tmp.path().join("s.duckdb"), "case-42", "/logs/prod").unwrap();

    let meta = store.case_meta().unwrap();

    assert_eq!(meta.case_id, "case-42");
    assert_eq!(meta.input_dir, "/logs/prod");
    assert!(!meta.app_version.is_empty());
}

#[test]
fn case_json_can_be_regenerated_after_deletion() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let store = Store::create(&dir.join("session.duckdb"), "case-9", "/logs").unwrap();

    store.write_case_json(dir).unwrap();
    std::fs::remove_file(dir.join("case.json")).unwrap();
    store.write_case_json(dir).unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("case.json")).unwrap()).unwrap();
    assert_eq!(json["case_id"], "case-9");
    assert_eq!(json["status"], "running");
    assert_eq!(json["event_count"], 0);
}

#[test]
fn re_evaluating_rules_replaces_matches_instead_of_duplicating() {
    use awslog_core::rule::Hit;

    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    let batch = vec![(
        "r1".to_string(),
        Hit {
            event_id: 1,
            matched_fields: Default::default(),
        },
    )];

    store.begin_rule_run(&[]).unwrap();
    store.append_match_batch(&batch).unwrap();
    store.begin_rule_run(&[]).unwrap();
    store.append_match_batch(&batch).unwrap();

    assert_eq!(store.match_count().unwrap(), 1);
}
