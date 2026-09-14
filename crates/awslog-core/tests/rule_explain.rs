//! Plain-language rendering of a parsed rule (docs/04).

use awslog_core::rule::{explain, RuleSet};

fn explained(src: &str) -> String {
    let set = RuleSet::from_source(src).unwrap();
    explain(&set.rules()[0])
}

#[test]
fn renders_a_single_comparison_in_words() {
    let text = explained(
        r#"rule r {
               meta: description = "d" severity = "high"
               fields: $n = event_name == "ConsoleLogin"
               condition: $n
           }"#,
    );

    // The author needs to confirm intent without re-reading the syntax.
    assert_eq!(text, "이벤트 이름 값이 \"ConsoleLogin\"");
}

#[test]
fn joins_conditions_with_korean_connectives() {
    let text = explained(
        r#"rule r {
               meta: description = "d" severity = "low"
               fields: $a = event_name == "ConsoleLogin"
                       $b = error_code exists
               condition: $a and $b
           }"#,
    );

    assert_eq!(
        text,
        "이벤트 이름 값이 \"ConsoleLogin\" 그리고 오류 코드 있음"
    );
}

#[test]
fn parenthesizes_a_nested_or_inside_an_and() {
    let text = explained(
        r#"rule r {
               meta: description = "d" severity = "low"
               fields: $a = event_name == "ConsoleLogin"
                       $b = source_ip == "203.0.113.10"
                       $c = source_ip == "198.51.100.7"
               condition: $a and ($b or $c)
           }"#,
    );

    // Without the parentheses the reading would change meaning.
    assert_eq!(
        text,
        "이벤트 이름 값이 \"ConsoleLogin\" 그리고 (출발지 IP 값이 \"203.0.113.10\" 또는 출발지 IP 값이 \"198.51.100.7\")"
    );
}

#[test]
fn renders_not_and_n_of() {
    let notted = explained(
        r#"rule r {
               meta: description = "d" severity = "low"
               fields: $a = mfa_authenticated == false
               condition: not $a
           }"#,
    );
    assert_eq!(notted, "다음이 아님 (MFA 사용 값이 false)");

    let nof = explained(
        r#"rule r {
               meta: description = "d" severity = "low"
               fields: $a = event_name == "A"
                       $b = event_name == "B"
                       $c = event_name == "C"
               condition: 2 of ($a, $b, $c)
           }"#,
    );
    assert_eq!(
        nof,
        "다음 중 2개: 이벤트 이름 값이 \"A\", 이벤트 이름 값이 \"B\", 이벤트 이름 값이 \"C\""
    );
}

#[test]
fn renders_every_operator_shape() {
    let cases = [
        (
            r#"$a = source_ip in ("1.1.1.1", "2.2.2.2")"#,
            "출발지 IP 값이 다음 중 하나: \"1.1.1.1\", \"2.2.2.2\"",
        ),
        (
            r#"$a = identity_arn contains "root""#,
            "주체 ARN 값에 \"root\" 포함",
        ),
        (
            r#"$a = user_agent icontains "curl""#,
            "User-Agent 값에 \"curl\" 포함(대소문자 무시)",
        ),
        (
            r#"$a = event_name startswith "Delete""#,
            "이벤트 이름 값이 \"Delete\"로 시작",
        ),
        (
            r#"$a = event_name endswith "Policy""#,
            "이벤트 이름 값이 \"Policy\"로 끝남",
        ),
        (
            r#"$a = error_message matches /denied/"#,
            "오류 메시지 값이 정규식 /denied/ 일치",
        ),
        (r#"$a = error_code missing"#, "오류 코드 없음"),
        (r#"$a = read_only != true"#, "읽기 전용 값이 true 아님"),
    ];

    for (field, expected) in cases {
        let src = format!(
            "rule r {{ meta: description = \"d\" severity = \"low\" fields: {field} condition: $a }}"
        );
        assert_eq!(explained(&src), expected, "for {field}");
    }
}

#[test]
fn an_undefined_variable_never_reaches_the_explanation() {
    // The parser rejects it, so the renderer's fallback is unreachable —
    // asserting the rejection is what actually holds.
    let err = RuleSet::from_source(
        r#"rule r {
               meta: description = "d" severity = "low"
               fields: $a = event_name == "A"
               condition: $a and $missing
           }"#,
    )
    .unwrap_err();

    assert!(err.to_string().contains("$missing"), "{err}");
}
