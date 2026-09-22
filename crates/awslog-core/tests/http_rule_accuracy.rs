//! Accuracy of the shipped HTTP rule pack (ALB, WAF, API Gateway, nginx).
//!
//! Every assertion runs the rule text compiled into the binary
//! (`RuleSet::shipped`), never a copy, and every event comes out of the real
//! parse pipeline, so the payload paths, JSON types and `-`/absent handling the
//! rules meet are the ones `parse.rs` and `ndjson.rs` produce.
//!
//! Fixtures are synthetic and masked (`203.0.113.x`, `000000000000`,
//! `example.test`).

mod support;

use std::sync::LazyLock;

use awslog_core::model::NormalizedEvent;
use awslog_core::parse::{self, ParseOptions};
use awslog_core::rule::{evaluate, RuleSet};
use awslog_core::store::Store;
use support::{apigw_record, gzip, nginx_record, write};

/// Every rule in this pack with the one log type it may run on.
const HTTP_RULES: [(&str, &str); 7] = [
    ("alb_server_error", "alb_access"),
    ("alb_forbidden_request", "alb_access"),
    ("alb_unusual_http_method", "alb_access"),
    ("waf_blocked_request", "waf_acl"),
    ("waf_injection_block", "waf_acl"),
    ("apigw_server_error", "apigw_access"),
    ("nginx_server_error", "nginx_access"),
];

/// The rule pack compiled into the binary; a pack that fails to load would
/// make every assertion below meaningless.
static SHIPPED: LazyLock<RuleSet> = LazyLock::new(|| {
    let set = RuleSet::shipped();
    assert!(set.errors().is_empty(), "{:?}", set.errors());
    set
});

/// Whether the shipped rule `id` fires on `event`. Also pins that the rule is
/// reachable for `log_type`: a missing or mistyped `meta: log_type` disables a
/// detection silently, with no load error.
fn hits(id: &str, log_type: &str, event: &NormalizedEvent) -> bool {
    let rule = SHIPPED
        .rule(id)
        .unwrap_or_else(|| panic!("shipped pack has no rule {id}"));
    assert!(rule.applies_to(log_type), "{id} does not run on {log_type}");
    evaluate(rule, event).is_some()
}

/// Parses gzipped fixtures through the real pipeline and returns the stored
/// events.
fn parsed(files: &[(&str, String)]) -> Vec<NormalizedEvent> {
    let dir = tempfile::tempdir().unwrap();
    for (name, contents) in files {
        write(&dir.path().join(name), &gzip(contents.as_bytes()));
    }
    let mut store = Store::create(&dir.path().join("session.duckdb"), "c1", "/logs").unwrap();
    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();
    assert_eq!(outcome.files_parsed, files.len(), "{outcome:?}");
    assert!(outcome.failures.is_empty(), "{outcome:?}");

    let mut events = Vec::new();
    store.for_each_event(|_, event| events.push(event)).unwrap();
    events
}

/// The single parsed event for one fixture case.
fn one(events: &[NormalizedEvent], keep: impl Fn(&NormalizedEvent) -> bool) -> &NormalizedEvent {
    let mut found = events.iter().filter(|&event| keep(event));
    let event = found.next().expect("fixture has no event for this case");
    assert!(found.next().is_none(), "fixture case is not unique");
    event
}

fn payload_has(payload: &Option<String>, needle: &str) -> bool {
    payload.as_deref().is_some_and(|text| text.contains(needle))
}

// ------------------------------------------------------------------- ALB

/// One ALB access line as the service writes it, including the `-`
/// placeholders and the `-1` timing sentinel used when no target answered.
fn alb_line(method: &str, url: &str, elb_status: &str, target_status: &str) -> String {
    // No target hop: no forward action, a `-1` timing sentinel and `-` in
    // every target column, exactly as the load balancer writes it.
    let (target, target_time, actions) = match target_status {
        "-" => ("-", "-1", "waf"),
        _ => ("10.0.0.10:8080", "0.003", "waf,forward"),
    };
    format!(
        concat!(
            "https 2026-08-18T23:50:00.405248Z app/masked-alb/0123456789abcdef ",
            "203.0.113.10:41234 {target} 0.001 {target_time} 0.000 ",
            "{elb_status} {target_status} 42 1150 ",
            "\"{method} {url} HTTP/1.1\" \"Masked Agent/1.0\" ",
            "TLS_AES_128_GCM_SHA256 TLSv1.3 ",
            "arn:aws:elasticloadbalancing:ap-northeast-2:000000000000:",
            "targetgroup/masked/0123456789abcdef ",
            "\"Root=1-masked\" \"example.test\" \"-\" 0 ",
            "2026-08-18T23:50:00.399000Z \"{actions}\" \"-\" \"-\" \"-\" \"-\" \"-\" \"-\"\n"
        ),
        target = target,
        target_time = target_time,
        actions = actions,
        elb_status = elb_status,
        target_status = target_status,
        method = method,
        url = url,
    )
}

/// One ALB file covering every status shape the rules have to judge.
static ALB: LazyLock<Vec<NormalizedEvent>> = LazyLock::new(|| {
    let lines = [
        alb_line("GET", "https://example.test/s404", "404", "404"),
        alb_line("GET", "https://example.test/s499", "499", "499"),
        alb_line("GET", "https://example.test/s500", "500", "500"),
        alb_line("GET", "https://example.test/s599", "599", "599"),
        // Out of the HTTP status range; the field is free text in the log line.
        alb_line("GET", "https://example.test/s600", "600", "600"),
        // No response was recorded at all.
        alb_line("GET", "https://example.test/none", "-", "-"),
        // 403 the load balancer itself produced (WAF decision, no target hop).
        alb_line("GET", "https://example.test/blocked", "403", "-"),
        // 403 the application produced and the load balancer relayed.
        alb_line("POST", "https://example.test/admin", "403", "403"),
        alb_line("GET", "https://example.test/unauth", "401", "401"),
        alb_line("CONNECT", "example.test:443", "400", "-"),
    ];
    parsed(&[("alb.log.gz", lines.concat())])
});

fn alb(url: &str) -> &'static NormalizedEvent {
    one(&ALB, |event| payload_has(&event.request, url))
}

#[test]
fn http_rules_are_scoped_to_the_single_log_type_they_interpret() {
    for (id, own) in HTTP_RULES {
        let rule = SHIPPED
            .rule(id)
            .unwrap_or_else(|| panic!("shipped pack has no rule {id}"));
        assert!(rule.applies_to(own), "{id} does not run on {own}");
        for other in [
            "cloudtrail",
            "alb_access",
            "waf_acl",
            "apigw_access",
            "nginx_access",
        ] {
            assert!(
                other == own || !rule.applies_to(other),
                "{id} also runs on {other}, where the same columns mean something else"
            );
        }
    }
}

#[test]
fn the_alb_server_error_rule_covers_the_5xx_range_and_nothing_outside_it() {
    assert!(hits("alb_server_error", "alb_access", alb("/s500")));
    assert!(hits("alb_server_error", "alb_access", alb("/s599")));
    assert!(!hits("alb_server_error", "alb_access", alb("/s499")));
    assert!(!hits("alb_server_error", "alb_access", alb("/s404")));
    assert!(
        !hits("alb_server_error", "alb_access", alb("/s600")),
        "600 is not an HTTP server error; the rule reports 5xx"
    );
    // The status column is genuinely absent, not zero: an inverted range
    // (`not ... < 500`) would report a request that never got a response.
    let none = alb("/none");
    assert!(payload_has(&none.response, r#""elb_status_code":null"#));
    assert!(!hits("alb_server_error", "alb_access", none));
}

#[test]
fn a_403_is_reported_whether_the_load_balancer_or_the_target_produced_it() {
    let by_balancer = alb("/blocked");
    let by_target = alb("/admin");

    assert!(hits("alb_forbidden_request", "alb_access", by_balancer));
    assert!(
        hits("alb_forbidden_request", "alb_access", by_target),
        "a 403 relayed from the target is still recorded as the ALB response"
    );
    assert!(!hits("alb_forbidden_request", "alb_access", alb("/unauth")));

    // Attribution lives in the payload, not in `error_code`: only the target's
    // own status separates the two cases above.
    assert!(payload_has(
        &by_balancer.response,
        r#""target_status_code":null"#
    ));
    assert!(payload_has(
        &by_target.response,
        r#""target_status_code":403"#
    ));
    assert_eq!(by_balancer.error_code.as_deref(), Some("HTTP 403"));
    assert_eq!(by_target.error_code.as_deref(), Some("HTTP 403"));
}

#[test]
fn the_unusual_method_rule_reads_the_method_parsed_out_of_the_request_line() {
    let connect = alb("example.test:443");
    assert_eq!(connect.event_name.as_deref(), Some("CONNECT"));
    assert!(hits("alb_unusual_http_method", "alb_access", connect));
    assert!(!hits("alb_unusual_http_method", "alb_access", alb("/s500")));
}

// ------------------------------------------------------ API Gateway, nginx

/// The parsed event one producer wrote with `status`.
fn with_status<'a>(
    events: &'a [NormalizedEvent],
    source: &str,
    status: u16,
) -> &'a NormalizedEvent {
    let needle = format!(r#""status":{status}"#);
    one(events, |event| {
        event.event_source.as_deref() == Some(source) && payload_has(&event.response, &needle)
    })
}

#[test]
fn api_gateway_and_nginx_status_strings_normalize_into_the_same_5xx_range() {
    let statuses = [499u16, 500, 599, 600];
    let file = |records: Vec<String>| format!("{}\n", records.join("\n"));
    let events = parsed(&[
        (
            "apigw.ndjson.gz",
            file(statuses.iter().map(|s| apigw_record(*s)).collect()),
        ),
        (
            "nginx.ndjson.gz",
            file(statuses.iter().map(|s| nginx_record(*s)).collect()),
        ),
    ]);
    for (rule, source, log_type) in [
        (
            "apigw_server_error",
            "apigateway.amazonaws.com",
            "apigw_access",
        ),
        ("nginx_server_error", "nginx", "nginx_access"),
    ] {
        // Exercise the producers' numeric-string status format through normalization.
        assert!(hits(rule, log_type, with_status(&events, source, 500)));
        assert!(hits(rule, log_type, with_status(&events, source, 599)));
        assert!(!hits(rule, log_type, with_status(&events, source, 499)));
        assert!(
            !hits(rule, log_type, with_status(&events, source, 600)),
            "{rule} reports 5xx, and 600 is outside the HTTP status range"
        );
    }
}

#[test]
fn waf_injection_uses_recorded_match_details_beyond_rule_names() {
    let cases = [
        ("BLOCK", "CommonRuleSet", "XSS", true),
        ("BLOCK", "custom-rule", "SQL_INJECTION", true),
        ("ALLOW", "CommonRuleSet", "XSS", false),
        ("BLOCK", "custom-rule", "OTHER", false),
        ("BLOCK", "custom-rule", "SQL_INJECTION_SUFFIX", false),
        ("BLOCK", "custom-rule", "", false),
        ("BLOCK", "SQLi-named-rule", "", true),
    ];
    let mut records = Vec::new();
    for (index, (action, rule, kind, _)) in cases.iter().enumerate() {
        let mut record: serde_json::Value =
            serde_json::from_str(&support::waf_record(action, rule)).unwrap();
        record["httpRequest"]["uri"] = serde_json::json!(format!("/case/{index}"));
        record["terminatingRuleMatchDetails"] = if kind.is_empty() {
            serde_json::json!([])
        } else {
            serde_json::json!([{"conditionType": kind, "matchedData": ["XSS", "SQL_INJECTION"]}])
        };
        records.push(record.to_string());
    }
    let events = parsed(&[("waf.ndjson.gz", format!("{}\n", records.join("\n")))]);
    for (index, (_, _, _, expected)) in cases.iter().enumerate() {
        let path = format!("/case/{index}");
        let event = one(&events, |event| payload_has(&event.request, &path));
        assert_eq!(
            hits("waf_injection_block", "waf_acl", event),
            *expected,
            "{index}"
        );
    }
}
