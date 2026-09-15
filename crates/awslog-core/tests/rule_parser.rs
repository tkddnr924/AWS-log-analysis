//! YARA-shaped rule syntax (docs/04-rule-format.md).

use awslog_core::rule::{parse_rules, Op, ParseRuleError};

const SAMPLE: &str = r#"
// Failed console logins.
rule cloudtrail_console_login_failure
{
    meta:
        description = "Failed AWS console login"
        severity    = "medium"
        log_type    = "cloudtrail"

    fields:
        $src  = event_source == "signin.amazonaws.com"
        $name = event_name   == "ConsoleLogin"
        $fail = response.ConsoleLogin == "Failure"

    condition:
        $src and $name and $fail
}
"#;

#[test]
fn parses_meta_fields_and_condition() {
    let rules = parse_rules(SAMPLE).unwrap();

    assert_eq!(rules.len(), 1);
    let rule = &rules[0];
    assert_eq!(rule.id, "cloudtrail_console_login_failure");
    assert_eq!(
        rule.meta.get("severity").map(String::as_str),
        Some("medium")
    );
    assert_eq!(
        rule.meta.get("log_type").map(String::as_str),
        Some("cloudtrail")
    );
    assert_eq!(rule.fields.len(), 3);

    let src = rule.fields.iter().find(|f| f.var == "$src").unwrap();
    assert_eq!(src.field, "event_source");
    assert_eq!(src.op, Op::Eq);
    assert_eq!(src.value.as_str(), Some("signin.amazonaws.com"));
}

#[test]
fn payload_keys_with_hyphens_are_field_paths_not_subtraction() {
    // S3 writes `x-amz-server-side-encryption`; the language has no
    // arithmetic, so a hyphen inside a path is part of the name. A negative
    // literal still parses: it always follows an operator.
    let rules = parse_rules(
        r#"rule sse {
               fields: $e = response.x-amz-server-side-encryption == "AES256"
                       $n = request.tagging.tagSet.0.key exists
                       $neg = response.delta < -1
               condition: $e and $n and $neg
           }"#,
    )
    .unwrap();

    let field = |var: &str| rules[0].fields.iter().find(|f| f.var == var).unwrap();
    assert_eq!(field("$e").field, "response.x-amz-server-side-encryption");
    assert_eq!(field("$n").field, "request.tagging.tagSet.0.key");
    assert_eq!(field("$neg").op, Op::Lt);
}

#[test]
fn keeps_dotted_paths_for_dynamic_fields() {
    let rules = parse_rules(SAMPLE).unwrap();
    let fail = rules[0].fields.iter().find(|f| f.var == "$fail").unwrap();

    // `response.*` is service-specific, so the path stays intact.
    assert_eq!(fail.field, "response.ConsoleLogin");
}

#[test]
fn parses_every_supported_operator() {
    let src = r#"
rule ops {
    fields:
        $a = event_name != "x"
        $b = user_agent contains "aws-cli"
        $c = identity_arn startswith "arn:aws:iam"
        $d = event_source endswith ".amazonaws.com"
        $e = event_name icontains "console"
        $f = error_code matches /^Access.*/
        $g = aws_region in ("ap-northeast-2", "us-east-1")
        $h = request.durationSeconds > 3600
        $i = error_code exists
        $j = error_message missing
    condition:
        $a
}
"#;
    let rules = parse_rules(src).unwrap();
    let ops: Vec<_> = rules[0].fields.iter().map(|f| f.op).collect();

    assert_eq!(
        ops,
        [
            Op::Ne,
            Op::Contains,
            Op::StartsWith,
            Op::EndsWith,
            Op::IContains,
            Op::Matches,
            Op::In,
            Op::Gt,
            Op::Exists,
            Op::Missing,
        ]
    );
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let src = r#"
/* block comment
   spanning lines */
rule commented { // trailing
    fields:
        $a = event_name == "x" // after a field
    condition:
        $a
}
"#;
    let rules = parse_rules(src).unwrap();
    assert_eq!(rules[0].id, "commented");
    assert_eq!(rules[0].fields.len(), 1);
}

#[test]
fn parses_multiple_rules_from_one_file() {
    let src = r#"
rule first  { fields: $a = event_name == "a" condition: $a }
rule second { fields: $b = event_name == "b" condition: $b }
"#;
    let rules = parse_rules(src).unwrap();
    let ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["first", "second"]);
}

#[test]
fn duplicate_rule_id_is_rejected() {
    let src = r#"
rule dup { fields: $a = event_name == "a" condition: $a }
rule dup { fields: $a = event_name == "b" condition: $a }
"#;
    let err = parse_rules(src).unwrap_err();
    assert!(matches!(err, ParseRuleError::DuplicateId { .. }), "{err}");
}

#[test]
fn condition_referencing_an_undefined_var_is_rejected() {
    let src = r#"
rule bad { fields: $a = event_name == "a" condition: $a and $missing }
"#;
    let err = parse_rules(src).unwrap_err();
    assert!(
        matches!(&err, ParseRuleError::UndefinedVar { var, .. } if var == "$missing"),
        "{err}"
    );
}

#[test]
fn unknown_symbol_is_rejected_pointing_at_the_line() {
    let src = r#"
rule bad { fields: $a = event_name ~= "a" condition: $a }
"#;
    let err = parse_rules(src).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("line 2"), "{message}");
    assert!(message.contains('~'), "{message}");
}

#[test]
fn unsupported_word_operator_names_the_rule_and_operator() {
    let src = r#"
rule bad { fields: $a = event_name likes "a" condition: $a }
"#;
    let err = parse_rules(src).unwrap_err();
    assert!(
        matches!(&err, ParseRuleError::UnsupportedOp { rule, op, .. } if rule == "bad" && op == "likes"),
        "{err}"
    );
}

#[test]
fn missing_condition_section_is_rejected() {
    let src = r#"rule bad { fields: $a = event_name == "a" }"#;
    assert!(parse_rules(src).is_err());
}

#[test]
fn every_parse_error_names_the_line_it_happened_on() {
    // The editor marks the line in the gutter; a message without a line
    // would leave the analyst hunting through the text.
    let line_of = |src: &str| parse_rules(src).unwrap_err().line();

    // A condition missing its field: the error is where `==` is, line 4.
    assert_eq!(
        line_of("rule r {\n    meta: description = \"x\"\n    fields:\n        $n = == \"a\"\n    condition: $n\n}"),
        Some(4)
    );
    // A field name where a variable should be, line 3.
    assert_eq!(
        line_of("rule r {\n    fields: $n = event_name == \"a\"\n    condition: event_name $n\n}"),
        Some(3)
    );
    // An undefined variable: the line it is used on.
    assert_eq!(
        line_of("rule r {\n    fields: $n = event_name == \"a\"\n\n    condition:\n        $n and $missing\n}"),
        Some(5)
    );
    // An unsupported operator word.
    assert_eq!(
        line_of("rule r {\n    fields: $n = event_name likes \"a\"\n    condition: $n\n}"),
        Some(2)
    );
    // Input that ends early: the last line there is.
    assert_eq!(
        line_of("rule r {\n    fields: $n = event_name == \"a\"\n"),
        Some(2)
    );
    // The lexer already knew its line.
    assert_eq!(
        line_of("rule r {\n    fields: $n = event_name ~= \"a\"\n    condition: $n\n}"),
        Some(2)
    );
    // Not a place in the text.
    assert_eq!(
        line_of("rule d { fields: $a = event_name == \"a\" condition: $a }\nrule d { fields: $a = event_name == \"a\" condition: $a }"),
        None
    );
}

#[test]
fn shipped_cloudtrail_pack_parses_with_practical_security_rules() {
    let rules = parse_rules(include_str!("../../../rules/cloudtrail.yar")).unwrap();
    let ids: Vec<_> = rules.iter().map(|rule| rule.id.as_str()).collect();

    assert_eq!(rules.len(), 11);
    for expected in [
        "cloudtrail_root_api_activity",
        "cloudtrail_iam_policy_change",
        "cloudtrail_access_key_created",
        "cloudtrail_kms_key_disruption",
        "cloudtrail_monitoring_disabled",
    ] {
        assert!(ids.contains(&expected), "missing shipped rule {expected}");
    }
}

#[test]
fn rule_sources_cut_each_rule_out_of_a_multi_rule_file() {
    // Braces inside strings and regexes must not end a rule early, and
    // comments between rules belong to neither.
    let src = r#"// pack header
rule first {
    meta: description = "has { brace }"
    fields: $a = event_name matches /x{2}/
    condition: $a
}
/* between */
rule second { fields: $b = event_name == "B" condition: $b }
"#;

    let sources = awslog_core::rule::rule_sources(src).unwrap();

    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].0, "first");
    assert!(sources[0].1.starts_with("rule first {"));
    assert!(sources[0].1.ends_with("condition: $a\n}"));
    assert_eq!(
        sources[1].1,
        r#"rule second { fields: $b = event_name == "B" condition: $b }"#
    );
    // The slice is itself a valid single rule, as the editor will save it.
    assert!(awslog_core::rule::parse_rules(&sources[0].1).is_ok());
}
