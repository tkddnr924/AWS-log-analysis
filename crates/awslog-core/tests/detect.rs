//! FR-3 content-based AWS log detection (docs/03-log-detection.md steps 2-3).

mod support;

use awslog_core::detect::{self, Confidence, LogType};
use support::{cloudtrail_json, cloudtrail_record, gzip, gzip_multi_member, write};

fn detect_bytes(name: &str, bytes: &[u8]) -> detect::Detection {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(name);
    write(&path, bytes);
    detect::detect_file(&path).unwrap()
}

#[test]
fn recognizes_cloudtrail_and_extracts_one_sample_record() {
    let json = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let d = detect_bytes("a.json.gz", &gzip(json.as_bytes()));

    assert_eq!(d.log_type, LogType::CloudTrail);
    assert_eq!(d.confidence, Confidence::High);

    let sample = d.sample.expect("first record summary");
    assert_eq!(sample.event_name.as_deref(), Some("ConsoleLogin"));
    assert_eq!(sample.event_source.as_deref(), Some("signin.amazonaws.com"));
    assert_eq!(sample.aws_region.as_deref(), Some("ap-northeast-2"));
    assert_eq!(sample.user_identity_type.as_deref(), Some("IAMUser"));
    assert_eq!(sample.source_ip_address.as_deref(), Some("203.0.113.10"));
}

#[test]
fn recognizes_alb_access_log_by_decompressed_record_shape() {
    let line = concat!(
        "h2 2026-08-18T23:50:00.405248Z ",
        "app/masked-alb/0123456789abcdef ",
        "203.0.113.10:39746 10.0.0.10:8080 0.002 0.003 0.000 200 200 ",
        "42 1150 \"GET https://example.test/path HTTP/2.0\" \"masked-agent\" ",
        "TLS_AES_128_GCM_SHA256 TLSv1.3 arn:aws:elasticloadbalancing:",
        "ap-northeast-2:000000000000:targetgroup/masked/0123456789abcdef ",
        "\"Root=1-masked\" \"example.test\" \"session-reused\" 1 ",
        "2026-08-18T23:50:00.399000Z \"waf,forward\" \"-\" \"-\" ",
        "\"10.0.0.10:8080\" \"200\" \"-\" \"-\" \"masked\" \"-\" \"-\" \"-\" ",
        "198.51.100.20\n",
    );

    let detection = detect_bytes("alb.log.gz", &gzip(line.as_bytes()));

    assert_eq!(detection.log_type, LogType::AlbAccess);
    assert_eq!(detection.confidence, Confidence::High);
    assert_eq!(detection.record_count_estimate, Some(1));
    let sample = detection.sample.expect("ALB sample");
    assert_eq!(
        sample.event_source.as_deref(),
        Some("elasticloadbalancing.amazonaws.com")
    );
    assert_eq!(sample.source_ip_address.as_deref(), Some("203.0.113.10"));
}

#[test]
fn reads_records_split_across_concatenated_gzip_members() {
    // Each member holds a complete JSON document; detection must decode past
    // the first member's trailer instead of stopping there.
    let first = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let second = cloudtrail_json(&[cloudtrail_record("AssumeRole")]);
    let bytes = gzip_multi_member(&[first.as_bytes(), second.as_bytes()]);

    let d = detect_bytes("multi.json.gz", &bytes);

    assert_eq!(d.log_type, LogType::CloudTrail);
    assert_eq!(d.members_in_head, 2);
}

#[test]
fn json_gz_that_is_not_cloudtrail_is_unknown() {
    let d = detect_bytes("other.json.gz", &gzip(br#"{"hello":"world"}"#));

    assert_eq!(d.log_type, LogType::Unknown);
    assert_eq!(d.confidence, Confidence::None);
    assert!(d.sample.is_none());
}

#[test]
fn records_present_but_missing_required_keys_is_low_confidence() {
    let json = r#"{"Records":[{"eventVersion":"1.08"}]}"#;
    let d = detect_bytes("partial.json.gz", &gzip(json.as_bytes()));

    assert_eq!(d.log_type, LogType::CloudTrail);
    assert_eq!(d.confidence, Confidence::Low);
}

#[test]
fn empty_records_array_is_cloudtrail_without_a_sample() {
    let d = detect_bytes("empty.json.gz", &gzip(br#"{"Records":[]}"#));

    assert_eq!(d.log_type, LogType::CloudTrail);
    assert!(d.sample.is_none());
}

#[test]
fn cloudtrail_digest_is_distinguished_from_event_logs() {
    let json = r#"{"digestPublicKeyFingerprint":"aa","logFiles":[]}"#;
    let d = detect_bytes("digest.json.gz", &gzip(json.as_bytes()));

    assert_eq!(d.log_type, LogType::CloudTrailDigest);
}

#[test]
fn damaged_gzip_header_is_reported_not_panicked() {
    let d = detect_bytes("broken.json.gz", b"not a gzip stream at all");

    assert_eq!(d.log_type, LogType::Unknown);
    assert_eq!(d.confidence, Confidence::None);
    assert!(d.note.as_deref().unwrap().contains("gzip"));
}

#[test]
fn truncated_gzip_body_still_yields_a_detection() {
    let json = cloudtrail_json(&[cloudtrail_record("ConsoleLogin")]);
    let full = gzip(json.as_bytes());
    let truncated = &full[..full.len() / 2];

    let d = detect_bytes("truncated.json.gz", truncated);

    // Damage must not abort the whole scan (NFR-4); it is reported per file.
    assert_eq!(d.log_type, LogType::Unknown);
    assert!(d.note.is_some());
}

#[test]
fn only_the_head_of_a_large_file_is_decoded() {
    let many: Vec<String> = (0..20_000)
        .map(|_| cloudtrail_record("ConsoleLogin"))
        .collect();
    let json = cloudtrail_json(&many);
    let d = detect_bytes("big.json.gz", &gzip(json.as_bytes()));

    assert_eq!(d.log_type, LogType::CloudTrail);
    assert!(
        d.decoded_bytes <= detect::HEAD_LIMIT,
        "decoded {} bytes, limit {}",
        d.decoded_bytes,
        detect::HEAD_LIMIT
    );
    // Record count from a partial read is an estimate, flagged as such.
    assert!(d.record_count_estimate.unwrap() > 0);
    assert!(d.estimated);
}

#[test]
fn large_fixture_actually_exceeds_the_head_limit() {
    // Guards the test above: if the fixture shrank below HEAD_LIMIT the
    // truncated-prefix path would silently stop being exercised.
    let many: Vec<String> = (0..20_000)
        .map(|_| cloudtrail_record("ConsoleLogin"))
        .collect();
    let json = cloudtrail_json(&many);
    assert!(
        json.len() > detect::HEAD_LIMIT * 4,
        "fixture is {} bytes, head limit {}",
        json.len(),
        detect::HEAD_LIMIT
    );
}

#[test]
fn record_estimate_for_a_large_file_is_close_to_the_real_count() {
    // 20k records exceed HEAD_LIMIT, so the count comes from the gzip
    // trailer plus the average record size seen in the head.
    let actual = 20_000;
    let many: Vec<String> = (0..actual)
        .map(|_| cloudtrail_record("ConsoleLogin"))
        .collect();
    let d = detect_bytes("big.json.gz", &gzip(cloudtrail_json(&many).as_bytes()));

    let estimate = d.record_count_estimate.expect("estimate") as f64;
    let error = (estimate - actual as f64).abs() / actual as f64;
    assert!(
        error < 0.10,
        "estimate {estimate} vs actual {actual} ({:.1}% off)",
        error * 100.0
    );
}

#[test]
fn recognizes_ndjson_producers_by_their_keys() {
    let waf = detect_bytes(
        "w.log.gz",
        &gzip(support::waf_record("BLOCK", "SQLi").as_bytes()),
    );
    assert_eq!(waf.log_type, detect::LogType::WafAcl);
    let sample = waf.sample.unwrap();
    assert_eq!(
        sample.event_time.as_deref(),
        Some("2026-08-31T03:22:19.583Z")
    );
    assert_eq!(sample.event_name.as_deref(), Some("BLOCK"));
    assert_eq!(sample.aws_region.as_deref(), Some("ap-northeast-2"));
    assert_eq!(sample.source_ip_address.as_deref(), Some("203.0.113.10"));

    let two = format!(
        "{}\n{}\n",
        support::apigw_record(200),
        support::apigw_record(502)
    );
    let apigw = detect_bytes("a.ndjson.gz", &gzip(two.as_bytes()));
    assert_eq!(apigw.log_type, detect::LogType::ApigwAccess);
    assert_eq!(apigw.record_count_estimate, Some(2));

    let nginx = detect_bytes("n.ndjson.gz", &gzip(support::nginx_record(200).as_bytes()));
    assert_eq!(nginx.log_type, detect::LogType::NginxAccess);
    assert_eq!(nginx.confidence, detect::Confidence::High);
}
