//! Rule evaluation against normalized events (docs/04-rule-format.md).

mod support;

use awslog_core::model::NormalizedEvent;
use awslog_core::rule::{evaluate, evaluate_any, parse_rules};
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
        response: Some(
            r#"{"ConsoleLogin":"Failure","x-amz-server-side-encryption":"AES256","delta":-3}"#
                .into(),
        ),
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
fn hyphenated_payload_keys_resolve_like_any_other_path() {
    let e = event();
    assert!(matches(
        &rule(r#"fields: $s = response.x-amz-server-side-encryption == "AES256" condition: $s"#),
        &e
    ));
    assert!(matches(
        &rule(r#"fields: $d = response.delta < -1 condition: $d"#),
        &e
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

/// The JSON shapes the evaluator special-cases: null, array, object, a
/// numeric string and a boolean written as a string.
fn shapes() -> NormalizedEvent {
    NormalizedEvent {
        request: Some(
            r#"{"count":"6","flag":"true","nothing":null,"items":[1,2],"nested":{"a":"b"},"amount":7200}"#
                .into(),
        ),
        ..event()
    }
}

#[test]
fn evidence_carries_every_field_that_fired_not_only_the_deciding_one() {
    // `$a or $c` is decided by `$a` alone and `$b` is never named in the
    // condition, yet every field that fired travels with the hit: the results
    // view explains the whole rule (docs/04 `matched_fields`).
    let rules = parse_rules(&rule(
        r#"fields:
             $a = event_name == "ConsoleLogin"
             $b = identity_type == "Root"
             $c = aws_region == "us-east-1"
           condition: $a or $c"#,
    ))
    .unwrap();

    let hit = evaluate(&rules[0], &event()).expect("match");

    assert_eq!(hit.rule_id, "t");
    assert_eq!(
        hit.matched_fields
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["$a", "$b"],
        "$c did not fire; $a and $b did"
    );
}

#[test]
fn a_variable_bound_twice_keeps_the_last_value_that_fired() {
    let both = parse_rules(&rule(
        r#"fields:
             $a = event_name == "ConsoleLogin"
             $a = identity_type == "Root"
           condition: $a"#,
    ))
    .unwrap();
    let hit = evaluate(&both[0], &event()).expect("match");
    assert_eq!(
        hit.matched_fields.get("$a").map(String::as_str),
        Some("Root")
    );

    // The variable holds when any of its bindings does, whichever came first.
    let second_only = parse_rules(&rule(
        r#"fields:
             $a = event_name == "AssumeRole"
             $a = identity_type == "Root"
           condition: $a"#,
    ))
    .unwrap();
    let hit = evaluate(&second_only[0], &event()).expect("match");
    assert_eq!(
        hit.matched_fields.get("$a").map(String::as_str),
        Some("Root")
    );

    let neither = parse_rules(&rule(
        r#"fields:
             $a = event_name == "AssumeRole"
             $a = identity_type == "IAMUser"
           condition: $a"#,
    ))
    .unwrap();
    assert!(evaluate(&neither[0], &event()).is_none());
}

#[test]
fn exists_reports_the_value_and_missing_reports_nothing() {
    let rules = parse_rules(&rule(
        "fields: $has = event_name exists $gone = error_code missing condition: $has and $gone",
    ))
    .unwrap();

    let hit = evaluate(&rules[0], &event()).expect("match");

    assert_eq!(
        hit.matched_fields.get("$has").map(String::as_str),
        Some("ConsoleLogin")
    );
    // Nothing was there, so the evidence for `missing` is empty.
    assert_eq!(
        hit.matched_fields.get("$gone").map(String::as_str),
        Some("")
    );
}

#[test]
fn evidence_renders_non_string_values_as_compact_json() {
    let rules = parse_rules(&rule(
        r#"fields:
             $num = request.amount exists
             $str = request.count exists
             $arr = request.items exists
             $obj = request.nested exists
             $flag = mfa_authenticated exists
             $whole = request exists
             $time = event_time exists
           condition: $num and $str and $arr and $obj and $flag and $whole and $time"#,
    ))
    .unwrap();
    let event = shapes();

    let fields = evaluate(&rules[0], &event).expect("match").matched_fields;

    assert_eq!(fields.get("$num").map(String::as_str), Some("7200"));
    assert_eq!(fields.get("$str").map(String::as_str), Some("6"));
    assert_eq!(fields.get("$arr").map(String::as_str), Some("[1,2]"));
    assert_eq!(fields.get("$obj").map(String::as_str), Some(r#"{"a":"b"}"#));
    assert_eq!(fields.get("$flag").map(String::as_str), Some("false"));
    // A whole JSON column reads back as the stored text, not a reprint.
    assert_eq!(
        fields.get("$whole").map(String::as_str),
        event.request.as_deref()
    );
    assert!(
        fields["$time"].starts_with("2026-09-11T02:03:04"),
        "event_time is RFC 3339 text: {}",
        fields["$time"]
    );
}

#[test]
fn case_insensitive_operators_fold_ascii_only() {
    let e = NormalizedEvent {
        user_agent: Some("사용자-AWS-CLI/2.15.0-Ä".into()),
        ..event()
    };

    assert!(matches(
        &rule(r#"fields: $a = user_agent icontains "aws-cli" condition: $a"#),
        &e
    ));
    assert!(matches(
        &rule(r#"fields: $a = user_agent istartswith "사용자-aws" condition: $a"#),
        &e
    ));
    assert!(matches(
        &rule(r#"fields: $a = user_agent iendswith "cli/2.15.0-Ä" condition: $a"#),
        &e
    ));
    // Only ASCII case is folded: `Ä` and `ä` stay different characters.
    assert!(!matches(
        &rule(r#"fields: $a = user_agent icontains "ä" condition: $a"#),
        &e
    ));
    // An empty needle is contained in anything.
    assert!(matches(
        &rule(r#"fields: $a = user_agent icontains "" condition: $a"#),
        &e
    ));
    assert!(!matches(
        &rule(r#"fields: $a = user_agent icontains "aws cli" condition: $a"#),
        &e
    ));

    // A long value — a whole raw record, say — answers the same as a short
    // one, either side of the length at which the search changes strategy.
    for pad in [0, 80, 90, 95, 96, 97, 400] {
        let padded = NormalizedEvent {
            user_agent: Some(format!("{}사용자-AWS-CLI/2.15.0-Ä", "x".repeat(pad))),
            ..event()
        };
        assert!(
            matches(
                &rule(r#"fields: $a = user_agent icontains "aws-cli" condition: $a"#),
                &padded
            ),
            "pad {pad}"
        );
        assert!(
            !matches(
                &rule(r#"fields: $a = user_agent icontains "ä" condition: $a"#),
                &padded
            ),
            "pad {pad}"
        );
        assert!(
            matches(
                &rule(r#"fields: $a = user_agent iendswith "cli/2.15.0-Ä" condition: $a"#),
                &padded
            ),
            "pad {pad}"
        );
    }
}

#[test]
fn comparisons_bridge_json_types_without_erroring() {
    let e = shapes();

    // A numeric string still compares numerically.
    assert!(matches(
        &rule(r#"fields: $a = request.count > 5 condition: $a"#),
        &e
    ));
    assert!(matches(
        &rule(r#"fields: $a = request.count == "6" condition: $a"#),
        &e
    ));
    // A JSON number equals its own text and its own number.
    assert!(matches(
        &rule(r#"fields: $a = request.amount == "7200" condition: $a"#),
        &e
    ));
    assert!(matches(
        &rule(r#"fields: $a = request.amount == 7200 condition: $a"#),
        &e
    ));
    // CloudTrail writes some booleans as strings.
    assert!(matches(
        &rule(r#"fields: $a = request.flag == true condition: $a"#),
        &e
    ));
    // A boolean column only equals a boolean literal.
    assert!(!matches(
        &rule(r#"fields: $a = mfa_authenticated == "false" condition: $a"#),
        &e
    ));
    // Containers are neither numeric nor equal to a scalar.
    assert!(!matches(
        &rule(r#"fields: $a = request.items > 1 condition: $a"#),
        &e
    ));
    assert!(!matches(
        &rule(r#"fields: $a = request.nested == "b" condition: $a"#),
        &e
    ));
}

#[test]
fn a_null_or_unreachable_json_path_counts_as_absent() {
    let e = shapes();

    assert!(matches(
        &rule("fields: $a = request.nothing missing condition: $a"),
        &e
    ));
    assert!(!matches(
        &rule("fields: $a = request.nothing exists condition: $a"),
        &e
    ));
    // Absent covers `!=` as well: there is nothing to differ from.
    assert!(!matches(
        &rule(r#"fields: $a = request.nothing != "x" condition: $a"#),
        &e
    ));
    // Walking through a scalar is absent, not an error.
    assert!(matches(
        &rule("fields: $a = request.count.deeper missing condition: $a"),
        &e
    ));
}

#[test]
fn regex_and_set_membership_see_the_rendered_value() {
    let e = shapes();

    assert!(matches(
        &rule(r#"fields: $a = request.amount matches /^7200$/ condition: $a"#),
        &e
    ));
    assert!(matches(
        &rule(r#"fields: $a = request.amount in ("7200") condition: $a"#),
        &e
    ));
    assert!(matches(
        &rule(r#"fields: $a = request.items in ("[1,2]") condition: $a"#),
        &e
    ));
    assert!(!matches(
        &rule(r#"fields: $a = request.items in ("[1, 2]") condition: $a"#),
        &e
    ));
}

#[test]
fn n_of_counts_each_listed_occurrence() {
    // The count is per listed entry, not per distinct variable.
    let body = r#"fields:
             $a = event_name == "ConsoleLogin"
             $b = aws_region == "us-east-1"
           condition: 2 of ($a, $a, $b)"#;
    assert!(matches(&rule(body), &event()));

    let strict = body.replace("2 of", "3 of");
    assert!(!matches(&rule(&strict), &event()));
}

#[test]
fn evaluate_any_agrees_with_evaluate() {
    // The boolean-only path (rule count preview) skips evidence entirely; it
    // must never disagree with the evaluator that produces it.
    let rules = parse_rules(
        r#"
rule hit { fields: $a = event_name == "ConsoleLogin" condition: $a }
rule miss { fields: $a = event_name == "AssumeRole" condition: $a }
rule negated { fields: $a = error_code exists condition: not $a }
rule counted {
    fields:
        $a = identity_type == "Root"
        $b = aws_region == "us-east-1"
        $c = request.durationSeconds > 3600
    condition: 2 of ($a, $b, $c)
}
rule nested {
    fields:
        $a = event_name == "ConsoleLogin"
        $b = event_name == "AssumeRole"
        $c = raw matches /ConsoleLogin/
    condition: ($a or $b) and not $b and $c
}
"#,
    )
    .unwrap();
    let events = [
        event(),
        shapes(),
        NormalizedEvent {
            event_name: None,
            raw: None,
            error_code: Some("AccessDenied".into()),
            ..event()
        },
    ];

    for e in &events {
        for r in &rules {
            assert_eq!(
                evaluate_any([r], e),
                evaluate(r, e).is_some(),
                "rule {}",
                r.id
            );
        }
        assert_eq!(
            evaluate_any(rules.iter(), e),
            rules.iter().any(|r| evaluate(r, e).is_some())
        );
    }

    // No rules can never match.
    assert!(!evaluate_any(rules[..0].iter(), &event()));
}
