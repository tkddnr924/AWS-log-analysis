//! FR-5 streaming parse into the session store.

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use awslog_core::parse::{self, ParseOptions, Progress};
use awslog_core::store::{CaseStatus, Store};
use awslog_core::{report, scan};
use support::{cloudtrail_json, cloudtrail_record, gzip, gzip_multi_member, write};

fn fixture_dir(files: &[(&str, Vec<u8>)]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    for (name, bytes) in files {
        write(&tmp.path().join(name), bytes);
    }
    tmp
}

fn alb_record(client: &str, request: &str, status: u16, error_reason: &str) -> String {
    format!(
        concat!(
            "h2 2026-08-18T23:50:00.405248Z app/masked-alb/0123456789abcdef ",
            "{client} 10.0.0.10:8080 0.002 0.003 0.000 {status} 200 42 1150 ",
            "\"{request}\" \"Masked Agent/1.0 with spaces\" ",
            "TLS_AES_128_GCM_SHA256 TLSv1.3 ",
            "arn:aws:elasticloadbalancing:ap-northeast-2:000000000000:",
            "targetgroup/masked/0123456789abcdef ",
            "\"Root=1-masked\" \"example.test\" \"session-reused\" 1 ",
            "2026-08-18T23:50:00.399000Z \"waf,forward\" \"-\" ",
            "\"{error_reason}\" \"10.0.0.10:8080\" \"200\" \"-\" \"-\" ",
            "\"masked-connection\" \"-\" \"-\" \"-\" \"future-field\"\n"
        ),
        client = client,
        status = status,
        request = request,
        error_reason = error_reason,
    )
}

fn parsed_events(store: &Store) -> Vec<awslog_core::model::NormalizedEvent> {
    let mut events = Vec::new();
    store.for_each_event(|_, event| events.push(event)).unwrap();
    events
}

#[test]
fn parses_every_record_into_the_store() {
    let json = cloudtrail_json(
        &(0..300)
            .map(|_| cloudtrail_record("ConsoleLogin"))
            .collect::<Vec<_>>(),
    );
    let dir = fixture_dir(&[("a.json.gz", gzip(json.as_bytes()))]);
    let db = dir.path().join("session.duckdb");
    let mut store = Store::create(&db, "c1", "/logs").unwrap();

    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    assert_eq!(outcome.records_parsed, 300);
    assert_eq!(store.event_count(&Default::default()).unwrap(), 300);
}

#[test]
fn normalizes_cloudtrail_fields_onto_the_rule_facing_names() {
    let json = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let dir = fixture_dir(&[("a.json.gz", gzip(json.as_bytes()))]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    let row = store.first_event().unwrap().unwrap();
    assert_eq!(row.event_name.as_deref(), Some("ConsoleLogin"));
    assert_eq!(
        row.identity_arn.as_deref(),
        Some("arn:aws:iam::000000000000:user/masked")
    );
}

#[test]
fn reads_all_members_of_a_concatenated_gzip() {
    let a = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let b = cloudtrail_json(&[
        cloudtrail_record("AssumeRole"),
        cloudtrail_record("GetCallerIdentity"),
    ]);
    let dir = fixture_dir(&[(
        "m.json.gz",
        gzip_multi_member(&[a.as_bytes(), b.as_bytes()]),
    )]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    assert_eq!(outcome.records_parsed, 3);
}

#[test]
fn a_damaged_file_is_reported_but_the_rest_still_parse() {
    let good = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let dir = fixture_dir(&[
        ("good.json.gz", gzip(good.as_bytes())),
        ("bad.json.gz", b"not gzip".to_vec()),
    ]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    assert_eq!(outcome.records_parsed, 1);
    assert_eq!(outcome.files_failed, 1);
    assert_eq!(outcome.files_parsed, 1);
}

#[test]
fn progress_reports_reach_the_caller_during_the_run() {
    let json = cloudtrail_json(
        &(0..50)
            .map(|_| cloudtrail_record("ConsoleLogin"))
            .collect::<Vec<_>>(),
    );
    let dir = fixture_dir(&[
        ("a.json.gz", gzip(json.as_bytes())),
        ("b.json.gz", gzip(json.as_bytes())),
    ]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();
    let seen = Mutex::new(Vec::<Progress>::new());

    parse::run(dir.path(), &mut store, &ParseOptions::default(), &|p| {
        seen.lock().push(p);
    })
    .unwrap();

    let seen = seen.into_inner();
    assert!(!seen.is_empty());
    let last = seen.last().unwrap();
    assert_eq!(last.files_done, 2);
    assert_eq!(last.files_total, 2);
}

#[test]
fn record_progress_advances_before_a_large_file_finishes() {
    let records = (0..25)
        .map(|_| {
            alb_record(
                "198.51.100.20:12345",
                "GET https://example.test/health HTTP/1.1",
                200,
                "-",
            )
        })
        .collect::<String>();
    let dir = fixture_dir(&[("large.log.gz", gzip(records.as_bytes()))]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();
    let seen = Mutex::new(Vec::<Progress>::new());
    let options = ParseOptions {
        batch_size: 10,
        ..Default::default()
    };

    parse::run(dir.path(), &mut store, &options, &|progress| {
        seen.lock().push(progress);
    })
    .unwrap();

    assert!(
        seen.into_inner()
            .iter()
            .any(|progress| progress.files_done == 0 && progress.records_parsed >= 10),
        "records must advance while the file is still active"
    );
}

#[test]
fn cancelling_stops_early_and_keeps_partial_results() {
    let json = cloudtrail_json(
        &(0..100)
            .map(|_| cloudtrail_record("ConsoleLogin"))
            .collect::<Vec<_>>(),
    );
    let files: Vec<_> = (0..8)
        .map(|i| (format!("f{i}.json.gz"), gzip(json.as_bytes())))
        .collect();
    let dir = fixture_dir(
        &files
            .iter()
            .map(|(n, b)| (n.as_str(), b.clone()))
            .collect::<Vec<_>>(),
    );
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let cancel = Arc::new(AtomicBool::new(false));
    let options = ParseOptions {
        cancel: Some(cancel.clone()),
        ..Default::default()
    };
    // Cancel as soon as the first file is done.
    let outcome = parse::run(dir.path(), &mut store, &options, &|p| {
        if p.files_done >= 1 {
            cancel.store(true, Ordering::Relaxed);
        }
    })
    .unwrap();

    assert!(outcome.cancelled);
    assert!(outcome.files_parsed < 8, "stopped early");
    assert!(
        store.event_count(&Default::default()).unwrap() > 0,
        "partial results kept"
    );

    store.finish(CaseStatus::Cancelled).unwrap();
    assert_eq!(store.case_status().unwrap(), CaseStatus::Cancelled);
}

#[test]
fn non_cloudtrail_file_is_skipped_without_failing_the_run() {
    let dir = fixture_dir(&[("other.json.gz", gzip(br#"{"hello":"world"}"#))]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    assert_eq!(outcome.records_parsed, 0);
    assert_eq!(outcome.files_skipped, 1);
    assert_eq!(outcome.files_failed, 0);
}

#[test]
fn parses_alb_access_log_into_rule_facing_fields() {
    let line = alb_record(
        "[2001:db8::10]:443",
        "GET https://example.test/admin?mode=full HTTP/2.0",
        502,
        "Target.ResponseCodeMismatch",
    );
    let dir = fixture_dir(&[("alb.log.gz", gzip(line.as_bytes()))]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    assert_eq!(outcome.records_parsed, 1);
    assert_eq!(outcome.files_parsed, 1);
    let event = parsed_events(&store).pop().unwrap();
    assert_eq!(event.event_name.as_deref(), Some("GET"));
    assert_eq!(
        event.event_source.as_deref(),
        Some("elasticloadbalancing.amazonaws.com")
    );
    assert_eq!(event.aws_region.as_deref(), Some("ap-northeast-2"));
    assert_eq!(event.account_id.as_deref(), Some("000000000000"));
    assert_eq!(event.source_ip.as_deref(), Some("2001:db8::10"));
    assert_eq!(
        event.user_agent.as_deref(),
        Some("Masked Agent/1.0 with spaces")
    );
    assert_eq!(event.error_code.as_deref(), Some("HTTP 502"));
    assert_eq!(
        event.error_message.as_deref(),
        Some("Target.ResponseCodeMismatch")
    );
    assert_eq!(event.read_only, Some(true));

    let request: serde_json::Value =
        serde_json::from_str(event.request.as_deref().unwrap()).unwrap();
    assert_eq!(request["url"], "https://example.test/admin?mode=full");
    assert_eq!(request["protocol"], "HTTP/2.0");
    let response: serde_json::Value =
        serde_json::from_str(event.response.as_deref().unwrap()).unwrap();
    assert_eq!(response["elb_status_code"], 502);
    assert_eq!(response["sent_bytes"], 1150);
    assert!(serde_json::from_str::<serde_json::Value>(event.raw.as_deref().unwrap()).is_ok());
}

#[test]
fn malformed_alb_lines_do_not_discard_valid_records() {
    let contents = format!(
        "not an ALB record\n{}broken second record\n",
        alb_record(
            "203.0.113.10:443",
            "POST https://example.test/login HTTP/1.1",
            403,
            "-"
        )
    );
    let dir = fixture_dir(&[("alb.log.gz", gzip(contents.as_bytes()))]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    assert_eq!(outcome.records_parsed, 1);
    assert_eq!(outcome.files_parsed, 1);
    assert_eq!(outcome.files_failed, 0);
    assert_eq!(outcome.failures.len(), 1);
    assert!(outcome.failures[0].reason.contains("2 malformed"));
}

#[test]
fn routes_cloudtrail_and_alb_files_through_their_own_parsers() {
    let cloudtrail = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let alb = alb_record(
        "198.51.100.20:12345",
        "GET https://example.test/health HTTP/1.1",
        200,
        "-",
    );
    let dir = fixture_dir(&[
        ("trail.json.gz", gzip(cloudtrail.as_bytes())),
        ("alb.log.gz", gzip(alb.as_bytes())),
    ]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    assert_eq!(outcome.records_parsed, 2);
    assert_eq!(outcome.files_parsed, 2);
    let sources: std::collections::HashSet<_> = parsed_events(&store)
        .into_iter()
        .filter_map(|event| event.event_source)
        .collect();
    assert_eq!(
        sources,
        [
            "signin.amazonaws.com".to_owned(),
            "elasticloadbalancing.amazonaws.com".to_owned()
        ]
        .into_iter()
        .collect()
    );

    let mut log_types = std::collections::HashSet::new();
    store
        .for_each_typed_event(|_, log_type, _| {
            log_types.insert(log_type.to_owned());
        })
        .unwrap();
    assert_eq!(
        log_types,
        ["cloudtrail".to_owned(), "alb_access".to_owned()]
            .into_iter()
            .collect()
    );
}

// getrusage is unix-only; the invariant is platform-independent so measuring
// it on one platform is enough.
#[cfg(unix)]
#[test]
fn memory_does_not_scale_with_file_size() {
    // The invariant is that peak memory tracks `batch_size`, not input size.
    // Tripling the record count must not triple the footprint (NFR-2).
    let small = parse_and_measure(20_000);
    let large = parse_and_measure(60_000);

    // No growth at all is the ideal outcome, and happens once the allocator
    // has already reached its high-water mark; only *scaling* is a failure.
    assert!(
        large <= small.max(1) * 2,
        "peak growth scaled with input: {small} -> {large} bytes for 3x records"
    );
}

/// Parses a synthetic file and returns peak RSS growth in bytes.
#[cfg(unix)]
fn parse_and_measure(records: usize) -> u64 {
    let json = cloudtrail_json(
        &(0..records)
            .map(|_| cloudtrail_record("ConsoleLogin"))
            .collect::<Vec<_>>(),
    );
    let dir = fixture_dir(&[("big.json.gz", gzip(json.as_bytes()))]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let before = peak_rss();
    let outcome = parse::run(
        dir.path(),
        &mut store,
        &ParseOptions {
            batch_size: 1_000,
            ..Default::default()
        },
        &|_| {},
    )
    .unwrap();
    assert_eq!(outcome.records_parsed, records as u64);
    peak_rss().saturating_sub(before)
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
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage.ru_maxrss as u64 * 1024
    }
}

#[test]
fn failure_reasons_are_returned_for_the_warning_log() {
    let dir = fixture_dir(&[("bad.json.gz", b"not gzip".to_vec())]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    assert_eq!(outcome.failures.len(), 1);
    let failure = &outcome.failures[0];
    assert_eq!(failure.display_path, "bad.json.gz");
    assert!(!failure.reason.is_empty());
    // The reason must not carry record content (FR-8).
    assert!(!failure.reason.contains('{'));
}

#[test]
fn console_login_mfa_comes_from_additional_event_data() {
    // Real ConsoleLogin records report MFA in additionalEventData.MFAUsed,
    // not in userIdentity.sessionContext (that is for assumed-role sessions).
    let record = r#"{
        "eventVersion": "1.08",
        "eventTime": "2026-09-11T02:03:04Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": { "type": "Root" },
        "additionalEventData": { "MFAUsed": "No" }
    }"#;
    let json = format!(r#"{{"Records":[{record}]}}"#);
    let dir = fixture_dir(&[("a.json.gz", gzip(json.as_bytes()))]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    let row = store.first_event().unwrap().unwrap();
    assert_eq!(row.mfa_authenticated, Some(false));
}

#[test]
fn parses_only_the_selected_files() {
    let json = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let dir = fixture_dir(&[
        ("keep.json.gz", gzip(json.as_bytes())),
        ("drop.json.gz", gzip(json.as_bytes())),
    ]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let options = ParseOptions {
        selected: Some(["keep.json.gz".to_owned()].into_iter().collect()),
        ..Default::default()
    };
    let outcome = parse::run(dir.path(), &mut store, &options, &|_| {}).unwrap();

    // Deselected files are not opened and not registered, so they cannot
    // show up later as "skipped" noise in the case database.
    assert_eq!(outcome.files_parsed, 1);
    assert_eq!(outcome.files_skipped, 0);
    assert_eq!(outcome.records_parsed, 1);
    assert_eq!(store.event_count(&Default::default()).unwrap(), 1);
}

#[test]
fn progress_total_counts_only_selected_files() {
    let json = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let dir = fixture_dir(&[
        ("a.json.gz", gzip(json.as_bytes())),
        ("b.json.gz", gzip(json.as_bytes())),
        ("c.json.gz", gzip(json.as_bytes())),
    ]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let options = ParseOptions {
        selected: Some(
            ["a.json.gz".to_owned(), "c.json.gz".to_owned()]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    };
    let seen = Mutex::new(Vec::new());
    parse::run(dir.path(), &mut store, &options, &|p: Progress| {
        seen.lock().push((p.files_done, p.files_total));
    })
    .unwrap();

    // Batch heartbeats may repeat a file count, but deselected files must
    // never enter the total and the final update must still reach it.
    let seen = seen.lock();
    assert!(seen.iter().all(|(done, total)| *total == 2 && *done <= 2));
    assert_eq!(seen.last(), Some(&(2, 2)));
}

#[test]
fn empty_selection_parses_nothing() {
    let json = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let dir = fixture_dir(&[("a.json.gz", gzip(json.as_bytes()))]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let options = ParseOptions {
        selected: Some(std::collections::HashSet::new()),
        ..Default::default()
    };
    let outcome = parse::run(dir.path(), &mut store, &options, &|_| {}).unwrap();

    assert_eq!(outcome.files_parsed, 0);
    assert_eq!(store.event_count(&Default::default()).unwrap(), 0);
}

#[test]
fn selection_keys_match_the_display_paths_the_ui_receives() {
    let json = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let dir = fixture_dir(&[
        (
            "AWSLogs/111/CloudTrail/ap-northeast-2/keep.json.gz",
            gzip(json.as_bytes()),
        ),
        (
            "AWSLogs/111/CloudTrail/ap-northeast-2/drop.json.gz",
            gzip(json.as_bytes()),
        ),
    ]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    // Take the key straight from what the UI is handed. This pins the
    // contract "displayed path == selection key" on every platform, instead
    // of restating the separator a literal would hard-code.
    let summary = report::summarize_scan(&scan::scan_dir(dir.path()).unwrap());
    let keep = summary
        .candidates
        .iter()
        .find(|c| c.display_path.ends_with("keep.json.gz"))
        .unwrap()
        .display_path
        .clone();
    assert!(
        keep.contains('/'),
        "nested fixture must exercise a subdirectory"
    );

    let options = ParseOptions {
        selected: Some([keep].into_iter().collect()),
        ..Default::default()
    };
    let outcome = parse::run(dir.path(), &mut store, &options, &|_| {}).unwrap();

    assert_eq!(outcome.files_parsed, 1);
    assert_eq!(store.event_count(&Default::default()).unwrap(), 1);
}

#[test]
fn ndjson_producers_normalize_onto_shared_http_columns() {
    let waf = format!(
        "{}\n{}\nnot json\n",
        support::waf_record("BLOCK", "AWS-AWSManagedRulesSQLiRuleSet"),
        support::waf_record("ALLOW", "Default_Action")
    );
    let dir = fixture_dir(&[
        ("waf.log.gz", gzip(waf.as_bytes())),
        (
            "apigw.ndjson.gz",
            gzip(support::apigw_record(502).as_bytes()),
        ),
        (
            "nginx.ndjson.gz",
            gzip(support::nginx_record(404).as_bytes()),
        ),
    ]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    assert_eq!(outcome.files_parsed, 3);
    assert_eq!(outcome.records_parsed, 4);
    let events = parsed_events(&store);
    let by_source = |src: &str| {
        events
            .iter()
            .filter(|e| e.event_source.as_deref() == Some(src))
            .collect::<Vec<_>>()
    };

    let waf = by_source("wafv2.amazonaws.com");
    assert_eq!(waf.len(), 2, "malformed line is skipped, not fatal");
    let blocked = waf
        .iter()
        .find(|e| e.event_name.as_deref() == Some("BLOCK"))
        .unwrap();
    assert_eq!(blocked.source_ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(blocked.aws_region.as_deref(), Some("ap-northeast-2"));
    assert_eq!(blocked.account_id.as_deref(), Some("000000000000"));
    assert_eq!(
        blocked.error_code.as_deref(),
        Some("AWS-AWSManagedRulesSQLiRuleSet")
    );
    let allowed = waf
        .iter()
        .find(|e| e.event_name.as_deref() == Some("ALLOW"))
        .unwrap();
    assert!(allowed.error_code.is_none(), "only a block is an error");
    let req: serde_json::Value = serde_json::from_str(blocked.request.as_deref().unwrap()).unwrap();
    assert_eq!(req["url"], "/v1/search?query=Aloe%20Extract");
    assert_eq!(req["country"], "KR");

    let apigw = by_source("apigateway.amazonaws.com")[0];
    assert_eq!(apigw.event_name.as_deref(), Some("GET"));
    assert_eq!(apigw.error_code.as_deref(), Some("HTTP 502"));
    let res: serde_json::Value = serde_json::from_str(apigw.response.as_deref().unwrap()).unwrap();
    assert_eq!(res["status"], 502, "string status becomes a number");

    let nginx = by_source("nginx")[0];
    assert_eq!(nginx.error_code.as_deref(), Some("HTTP 404"));
    assert_eq!(nginx.source_ip.as_deref(), Some("203.0.113.30"));
    let req: serde_json::Value = serde_json::from_str(nginx.request.as_deref().unwrap()).unwrap();
    assert_eq!(req["url"], "api.example.test/v1/products/1");

    // The results view reads status the same way for every HTTP producer.
    let page = awslog_core::results::all_events(
        &store,
        &awslog_core::results::Window {
            limit: 10,
            ..Default::default()
        },
    )
    .unwrap();
    let statuses: std::collections::HashSet<_> =
        page.rows.iter().filter_map(|r| r.status.clone()).collect();
    assert_eq!(
        statuses,
        ["502".to_owned(), "404".to_owned()].into_iter().collect()
    );
    let time_of = |lt: &str| {
        page.rows
            .iter()
            .find(|r| r.log_type == lt)
            .and_then(|r| r.event_time.clone())
    };
    assert_eq!(
        time_of("apigw_access").as_deref(),
        Some("2026-08-31 09:00:05.000"),
        "CLF time, KST"
    );
    assert_eq!(
        time_of("nginx_access").as_deref(),
        Some("2026-08-31 15:24:00.004")
    );
    let waf_row = page
        .rows
        .iter()
        .find(|r| {
            r.log_type == "waf_acl" && r.rule.as_deref() == Some("AWS-AWSManagedRulesSQLiRuleSet")
        })
        .unwrap();
    assert_eq!(waf_row.country.as_deref(), Some("KR"));
    assert_eq!(
        waf_row.event_time.as_deref(),
        Some("2026-08-31 12:22:19.583"),
        "epoch millis, KST"
    );
}

#[test]
fn every_payload_path_seen_while_parsing_is_recorded_per_log_type() {
    // Nothing is declared up front: whatever the producers put inside
    // requestParameters / responseElements / resources (or the HTTP
    // request/response objects) becomes a known path the rule editor can
    // offer, with how many events carried it.
    let dir = fixture_dir(&[
        (
            "trail.json.gz",
            gzip(
                cloudtrail_json(&[
                    cloudtrail_record("ConsoleLogin"),
                    cloudtrail_record("ConsoleLogin"),
                ])
                .as_bytes(),
            ),
        ),
        (
            "waf.log.gz",
            gzip(support::waf_record("BLOCK", "rule").as_bytes()),
        ),
        (
            "alb.log.gz",
            gzip(alb_record("203.0.113.5:1", "GET https://x/ HTTP/1.1", 503, "-").as_bytes()),
        ),
    ]);
    let mut store = Store::create(&dir.path().join("s.duckdb"), "c1", "/logs").unwrap();

    parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();

    let keys = |log_type: Option<&str>| {
        awslog_core::results::payload_keys(&store, log_type)
            .unwrap()
            .into_iter()
            .map(|k| (k.log_type, k.path, k.events))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        keys(Some("cloudtrail")),
        [(
            "cloudtrail".to_owned(),
            "response.ConsoleLogin".to_owned(),
            2
        )]
    );
    let waf = keys(Some("waf_acl"));
    assert!(waf
        .iter()
        .any(|(_, path, n)| path == "request.country" && *n == 1));
    assert!(waf
        .iter()
        .any(|(_, path, _)| path == "response.match_details.0.location"));
    let alb = keys(Some("alb_access"));
    assert!(alb
        .iter()
        .any(|(_, path, _)| path == "response.elb_status_code"));
    // Every type at once, most frequent first within a type.
    let all = keys(None);
    assert_eq!(all.len(), 1 + waf.len() + alb.len());
    assert!(all.windows(2).all(|w| w[0].0 != w[1].0 || w[0].2 >= w[1].2));
}
