//! Rule evaluation against normalized events (docs/04-rule-format.md).

mod support;

use awslog_core::model::NormalizedEvent;
use awslog_core::rule::{evaluate, parse_rules};
use time::macros::datetime;

fn event() -> NormalizedEvent {
    NormalizedEvent {
        file_id: 0,
        record_index: 0,
        event_time: Some(datetime!(2026-09-11 02:03:04).assume_utc()),
        event_source: Some("signin.amazonaws.com".into()),
        event_name: Some("ConsoleLogin".into()),
        aws_region: Some("ap-northeast-2".into()),
        account_id: Some("000000000000".into()),
        source_ip: Some("203.0.113.10".into()),
        user_agent: Some("aws-cli/2.15.0".into()),
        identity_type: Some("Root".into()),
        identity_arn: Some("arn:aws:iam::000000000000:root".into()),
        identity_name: None,
        mfa_authenticated: Some(false),
        error_code: None,
        error_message: None,
        read_only: Some(false),
        management_event: Some(true),
        request: Some(r#"{"durationSeconds":7200}"#.into()),
        response: Some(r#"{"ConsoleLogin":"Failure"}"#.into()),
        resources: None,
        raw: Some(r#"{"eventName":"ConsoleLogin"}"#.into()),
    }
}

fn matches(rule_src: &str, event: &NormalizedEvent) -> bool {
    let rules = parse_rules(rule_src).unwrap();
    evaluate(&rules[0], event).is_some()
}

fn rule(body: &str) -> String {
    format!("rule t {{ {body} }}")
}

#[test]
fn equality_and_negation_compare_normalized_fields() {
    assert!(matches(
        &rule(r#"fields: $a = event_name == "ConsoleLogin" condition: $a"#),
        &event()
    ));
    assert!(!matches(
        &rule(r#"fields: $a = event_name == "AssumeRole" condition: $a"#),
        &event()
    ));
    assert!(matches(
        &rule(r#"fields: $a = event_name != "AssumeRole" condition: $a"#),
        &event()
    ));
}

#[test]
fn substring_operators_respect_case_sensitivity() {
    let e = event();
    assert!(matches(
        &rule(r#"fields: $a = user_agent contains "aws-cli" condition: $a"#),
        &e
    ));
    assert!(!matches(
        &rule(r#"fields: $a = user_agent contains "AWS-CLI" condition: $a"#),
        &e
    ));
    assert!(matches(
        &rule(r#"fields: $a = user_agent icontains "AWS-CLI" condition: $a"#),
        &e
    ));
}

#[test]
fn regex_and_set_membership_work() {
    let e = event();
    assert!(matches(
        &rule(r#"fields: $a = identity_arn matches /:root$/ condition: $a"#),
        &e
    ));
    assert!(matches(
        &rule(r#"fields: $a = aws_region in ("us-east-1", "ap-northeast-2") condition: $a"#),
        &e
    ));
    assert!(!matches(
        &rule(r#"fields: $a = aws_region in ("us-east-1") condition: $a"#),
        &e
    ));
}

#[test]
fn numeric_comparison_reads_through_dynamic_json_paths() {
    let e = event();
    assert!(matches(
        &rule(r#"fields: $a = request.durationSeconds > 3600 condition: $a"#),
        &e
    ));
    assert!(!matches(
        &rule(r#"fields: $a = request.durationSeconds > 7200 condition: $a"#),
        &e
    ));
}

#[test]
fn response_path_matches_string_values() {
    assert!(matches(
        &rule(r#"fields: $a = response.ConsoleLogin == "Failure" condition: $a"#),
        &event()
    ));
}

#[test]
fn exists_and_missing_distinguish_absent_fields() {
    let e = event();
    assert!(matches(
        &rule("fields: $a = error_code missing condition: $a"),
        &e
    ));
    assert!(!matches(
        &rule("fields: $a = error_code exists condition: $a"),
        &e
    ));
    assert!(matches(
        &rule("fields: $a = event_name exists condition: $a"),
        &e
    ));
}

#[test]
fn absent_field_never_satisfies_a_value_comparison() {
    // A missing field must not silently compare equal to anything.
    assert!(!matches(
        &rule(r#"fields: $a = error_code == "AccessDenied" condition: $a"#),
        &event()
    ));
}

#[test]
fn type_mismatch_does_not_match_instead_of_erroring() {
    // Comparing a string field numerically is a rule bug, not an event error.
    assert!(!matches(
        &rule("fields: $a = event_name > 5 condition: $a"),
        &event()
    ));
}

#[test]
fn boolean_fields_compare_against_literals() {
    let e = event();
    assert!(matches(
        &rule("fields: $a = mfa_authenticated == false condition: $a"),
        &e
    ));
    assert!(matches(
        &rule("fields: $a = management_event == true condition: $a"),
        &e
    ));
}

#[test]
fn condition_honours_and_or_not_and_parentheses() {
    let e = event();
    let src = rule(
        r#"fields:
             $a = event_name == "ConsoleLogin"
             $b = event_name == "AssumeRole"
             $c = identity_type == "Root"
           condition:
             ($a or $b) and not $b and $c"#,
    );
    assert!(matches(&src, &e));
}

#[test]
fn n_of_counts_satisfied_vars() {
    let e = event();
    let body = r#"fields:
             $a = event_name == "ConsoleLogin"
             $b = identity_type == "Root"
             $c = aws_region == "us-east-1"
           condition:
             2 of ($a, $b, $c)"#;
    assert!(matches(&rule(body), &e));

    let strict = body.replace("2 of", "3 of");
    assert!(!matches(&rule(&strict), &e));
}

#[test]
fn match_reports_which_fields_fired_and_their_values() {
    let rules = parse_rules(&rule(
        r#"fields:
             $src = event_source == "signin.amazonaws.com"
             $who = identity_type == "Root"
           condition: $src and $who"#,
    ))
    .unwrap();

    let hit = evaluate(&rules[0], &event()).expect("match");

    // The results view shows why a rule fired without re-evaluating it.
    assert_eq!(
        hit.matched_fields.get("$src").map(String::as_str),
        Some("signin.amazonaws.com")
    );
    assert_eq!(
        hit.matched_fields.get("$who").map(String::as_str),
        Some("Root")
    );
}

#[test]
fn raw_escape_hatch_exposes_the_original_record() {
    assert!(matches(
        &rule(r#"fields: $a = raw contains "ConsoleLogin" condition: $a"#),
        &event()
    ));
}
