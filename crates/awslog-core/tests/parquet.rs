//! Parquet input: scan, detect, preview and parse (docs/03 "Parquet").

mod support;

use std::path::Path;

use awslog_core::detect::{self, Confidence, LogType};
use awslog_core::mapping::FieldMap;
use awslog_core::parse::{self, ParseOptions};
use awslog_core::store::Store;
use awslog_core::{preview, scan};
use support::{waf_record, write};

/// Writes NDJSON `lines` as a Parquet file, letting DuckDB infer the
/// column types the way an export pipeline would.
fn write_parquet(path: &Path, lines: &[String]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let ndjson = path.with_extension("ndjson.tmp");
    std::fs::write(&ndjson, lines.join("\n")).unwrap();
    let conn = duckdb::Connection::open_in_memory().unwrap();
    conn.execute_batch(&format!(
        "COPY (SELECT * FROM read_json('{}')) TO '{}' (FORMAT parquet)",
        ndjson.display(),
        path.display()
    ))
    .unwrap();
    std::fs::remove_file(ndjson).unwrap();
}

/// One API gateway request row, masked. Headers arrive as a JSON string.
fn gateway_row(member: u64, method: &str, path: &str) -> String {
    let headers = serde_json::json!({
        "host": "api.example.test",
        "user-agent": "okhttp/4.12.0",
        "auth-type": "member",
    })
    .to_string();
    serde_json::json!({
        "requestedtimeutc": "2026-08-31 00:00:05.123",
        "memberid": member,
        "sourceip": "203.0.113.40, 10.0.0.7",
        "httpmethod": method,
        "apipath": path,
        "apiparams": "page=2",
        "requestheaders": headers,
        "requestbody": "{\"q\":\"aloe\"}",
        "datadogtraceid": "1234567890",
    })
    .to_string()
}

fn gateway_file(dir: &Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    write_parquet(
        &path,
        &[
            gateway_row(42, "POST", "/user/v3/events/1/meta"),
            gateway_row(0, "GET", "/hospital/names"),
            gateway_row(42, "GET", "/hospital/names"),
        ],
    );
    path
}

#[test]
fn parquet_files_are_scan_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    gateway_file(tmp.path(), "2026/08/31/00/part-0.parquet");
    gateway_file(tmp.path(), "UPPER.PARQUET");
    write(&tmp.path().join("notes.txt"), b"x");

    let report = scan::scan_dir(tmp.path()).unwrap();

    assert_eq!(report.candidates.len(), 2);
    assert_eq!(report.skipped.len(), 1);
}

#[test]
fn detects_gateway_requests_in_parquet_with_exact_row_count() {
    let tmp = tempfile::tempdir().unwrap();
    let path = gateway_file(tmp.path(), "a.parquet");

    let d = detect::detect_file(&path).unwrap();

    assert_eq!(d.log_type, LogType::GatewayRequest);
    assert_eq!(d.confidence, Confidence::High);
    // Parquet footers carry the row count, so nothing is extrapolated.
    assert_eq!(d.record_count_estimate, Some(3));
    assert!(!d.estimated);
    let sample = d.sample.expect("first row summary");
    assert_eq!(sample.event_name.as_deref(), Some("POST"));
    assert_eq!(
        sample.event_time.as_deref(),
        Some("2026-08-31T00:00:05.123Z")
    );
    assert_eq!(
        sample.source_ip_address.as_deref(),
        Some("203.0.113.40"),
        "first hop of the X-Forwarded-For chain"
    );
}

#[test]
fn parquet_holding_a_known_ndjson_producer_is_detected_as_that_producer() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("waf.parquet");
    write_parquet(
        &path,
        &[waf_record("BLOCK", "AWS-AWSManagedRulesSQLiRuleSet")],
    );

    let d = detect::detect_file(&path).unwrap();

    assert_eq!(d.log_type, LogType::WafAcl);
    assert_eq!(d.record_count_estimate, Some(1));
}

#[test]
fn unrelated_or_damaged_parquet_is_unknown_with_a_note() {
    let tmp = tempfile::tempdir().unwrap();
    let other = tmp.path().join("other.parquet");
    write_parquet(&other, &[r#"{"a":1,"b":"x"}"#.to_owned()]);
    let damaged = tmp.path().join("damaged.parquet");
    write(&damaged, b"PAR1 this is not a parquet footer PAR1");

    let other = detect::detect_file(&other).unwrap();
    assert_eq!(other.log_type, LogType::Unknown);

    let damaged = detect::detect_file(&damaged).unwrap();
    assert_eq!(damaged.log_type, LogType::Unknown);
    assert_eq!(damaged.confidence, Confidence::None);
    assert!(damaged.note.is_some());
}

#[test]
fn preview_reads_parquet_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let path = gateway_file(tmp.path(), "a.parquet");

    let p = preview::preview_head(&path, LogType::GatewayRequest, &FieldMap::cloudtrail()).unwrap();

    assert_eq!(p.records, 3);
    assert_eq!(p.mapped, 3);
    let field_of = |raw: &str| {
        p.pieces
            .iter()
            .find(|piece| piece.path == raw)
            .and_then(|piece| piece.field.clone())
    };
    assert_eq!(field_of("apipath").as_deref(), Some("request.url"));
    assert_eq!(field_of("sourceip").as_deref(), Some("source_ip"));
}

#[test]
fn parses_gateway_parquet_rows_into_normalized_events() {
    let tmp = tempfile::tempdir().unwrap();
    gateway_file(tmp.path(), "logs/2026/08/31/00/a.parquet");
    gateway_file(tmp.path(), "logs/2026/08/31/01/b.parquet");
    let db = tmp.path().join("session.duckdb");
    let mut store = Store::create(&db, "c1", "/logs").unwrap();
    let options = ParseOptions {
        batch_size: 2,
        ..ParseOptions::default()
    };

    let outcome = parse::run(&tmp.path().join("logs"), &mut store, &options, &|_| {}).unwrap();

    assert_eq!(outcome.files_parsed, 2);
    assert_eq!(outcome.files_failed, 0);
    assert_eq!(outcome.records_parsed, 6);
    let mut events = Vec::new();
    store.for_each_event(|_, e| events.push(e)).unwrap();
    let post = events
        .iter()
        .find(|e| e.event_name.as_deref() == Some("POST"))
        .unwrap();
    assert_eq!(post.event_source.as_deref(), Some("api-gateway"));
    assert_eq!(
        post.event_time.map(|t| t.unix_timestamp_nanos()),
        Some(1_788_134_405_123_000_000),
        "naive timestamp is UTC"
    );
    assert_eq!(post.source_ip.as_deref(), Some("203.0.113.40"));
    assert_eq!(post.user_agent.as_deref(), Some("okhttp/4.12.0"));
    assert_eq!(post.identity_type.as_deref(), Some("member"));
    assert_eq!(post.identity_name.as_deref(), Some("42"));
    assert_eq!(post.read_only, Some(false));
    let req: serde_json::Value = serde_json::from_str(post.request.as_deref().unwrap()).unwrap();
    assert_eq!(req["url"], "/user/v3/events/1/meta");
    assert_eq!(req["params"], "page=2");
    assert_eq!(req["body"], "{\"q\":\"aloe\"}");
    assert_eq!(req["trace_id"], "1234567890");
    assert_eq!(req["forwarded_for"], "203.0.113.40, 10.0.0.7");
    assert_eq!(req["headers"]["auth-type"], "member");
    let res: serde_json::Value = serde_json::from_str(post.resources.as_deref().unwrap()).unwrap();
    assert_eq!(res["host"], "api.example.test");

    let anonymous = events
        .iter()
        .find(|e| e.identity_type.as_deref() == Some("anonymous"))
        .unwrap();
    assert_eq!(anonymous.identity_name, None, "member 0 is no one");
    assert_eq!(anonymous.read_only, Some(true));
}
