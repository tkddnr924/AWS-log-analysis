//! Rule loading from disk and match aggregation for the results view.

mod support;

use awslog_core::model::NormalizedEvent;
use awslog_core::rule::{self, RuleSet};
use support::write;
use time::macros::datetime;

fn event(name: &str, identity: &str) -> NormalizedEvent {
    NormalizedEvent {
        file_id: 0,
        record_index: 0,
        event_time: Some(datetime!(2026-09-11 02:03:04).assume_utc()),
        event_source: Some("signin.amazonaws.com".into()),
        event_name: Some(name.into()),
        aws_region: Some("ap-northeast-2".into()),
        account_id: None,
        source_ip: None,
        user_agent: None,
        identity_type: Some(identity.into()),
        identity_arn: None,
        identity_name: None,
        mfa_authenticated: Some(false),
        error_code: None,
        error_message: None,
        read_only: Some(false),
        management_event: Some(true),
        request: None,
        response: None,
        resources: None,
        raw: None,
    }
}

const GOOD: &str = r#"
rule root_login {
    meta: description = "Root console login" severity = "high"
    fields:
        $name = event_name == "ConsoleLogin"
        $root = identity_type == "Root"
    condition: $name and $root
}
"#;

#[test]
fn loads_every_rule_file_in_a_directory() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("a.yar"), GOOD.as_bytes());
    write(
        &tmp.path().join("b.yar"),
        br#"rule any_login { fields: $a = event_name == "ConsoleLogin" condition: $a }"#,
    );
    // Non-rule files are ignored, not treated as errors.
    write(&tmp.path().join("notes.txt"), b"ignore me");

    let set = RuleSet::load_dir(tmp.path()).unwrap();

    assert_eq!(set.rules().len(), 2);
    assert!(set.errors().is_empty());
}

#[test]
fn a_broken_rule_file_disables_only_itself() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("good.yar"), GOOD.as_bytes());
    write(&tmp.path().join("broken.yar"), b"rule oops { fields: $a = ");

    let set = RuleSet::load_dir(tmp.path()).unwrap();

    assert_eq!(set.rules().len(), 1, "the valid rule still loads");
    assert_eq!(set.errors().len(), 1);
    assert!(set.errors()[0].path.ends_with("broken.yar"));
    assert!(!set.errors()[0].message.is_empty());
}

#[test]
fn matching_groups_hits_by_rule_and_counts_unmatched() {
    let set = RuleSet::from_source(GOOD).unwrap();
    let events = [
        event("ConsoleLogin", "Root"),    // matches
        event("ConsoleLogin", "IAMUser"), // no: not root
        event("AssumeRole", "Root"),      // no: wrong event
    ];

    let report = rule::match_events(&set, events.iter().enumerate().map(|(i, e)| (i as u64, e)));

    assert_eq!(report.groups.len(), 1);
    let group = &report.groups[0];
    assert_eq!(group.rule_id, "root_login");
    assert_eq!(group.severity, "high");
    assert_eq!(group.description, "Root console login");
    assert_eq!(group.matches.len(), 1);
    assert_eq!(group.matches[0].event_id, 0);

    // Every event is accounted for: matched + unmatched == total (docs/04).
    assert_eq!(report.unmatched, 2);
    assert_eq!(report.total, 3);
}

#[test]
fn an_event_can_match_several_rules() {
    let src = format!(
        "{GOOD}\nrule any_login {{ fields: $a = event_name == \"ConsoleLogin\" condition: $a }}"
    );
    let set = RuleSet::from_source(&src).unwrap();

    let report = rule::match_events(&set, [(7u64, &event("ConsoleLogin", "Root"))]);

    assert_eq!(report.groups.len(), 2);
    assert_eq!(report.unmatched, 0);
    // One event, matched twice: the count is of events, not of hits.
    assert_eq!(report.total, 1);
}

#[test]
fn log_type_meta_restricts_which_rules_apply() {
    let src = r#"
rule only_vpc {
    meta: log_type = "vpc_flow"
    fields: $a = event_name == "ConsoleLogin"
    condition: $a
}
"#;
    let set = RuleSet::from_source(src).unwrap();

    let applicable = set.for_log_type("cloudtrail").count();

    assert_eq!(applicable, 0, "a vpc-only rule must not run on cloudtrail");
}

#[test]
fn matched_fields_travel_with_the_hit() {
    let set = RuleSet::from_source(GOOD).unwrap();

    let report = rule::match_events(&set, [(3u64, &event("ConsoleLogin", "Root"))]);

    let hit = &report.groups[0].matches[0];
    assert_eq!(
        hit.matched_fields.get("$root").map(String::as_str),
        Some("Root")
    );
    assert_eq!(
        hit.matched_fields.get("$name").map(String::as_str),
        Some("ConsoleLogin")
    );
}

#[test]
fn shipped_rules_parse_and_are_scoped_to_their_log_types() {
    // The rule pack compiled into the binary must stay loadable; a typo here
    // would silently disable detections for every user.
    let set = RuleSet::shipped();

    assert!(set.errors().is_empty(), "{:?}", set.errors());
    // Every shipped rule stays gated to the log type it declares: a stray
    // gate would run CloudTrail logic against web access logs.
    for log_type in [
        "cloudtrail",
        "alb_access",
        "waf_acl",
        "apigw_access",
        "nginx_access",
    ] {
        assert!(
            set.for_log_type(log_type).count() > 0,
            "no shipped rule runs for {log_type}"
        );
        for rule in set.for_log_type(log_type) {
            assert_eq!(
                rule.meta.get("log_type").map(String::as_str),
                Some(log_type),
                "{} leaked into {log_type}",
                rule.id
            );
        }
    }

    // Every shipped rule carries the metadata the results view displays.
    for rule in set.rules() {
        assert!(
            !rule.description().is_empty(),
            "{} lacks description",
            rule.id
        );
        // The sidebar shows the name alone, so a shipped rule must not fall
        // back to its id.
        assert_ne!(rule.name(), rule.id, "{} lacks name", rule.id);
        assert_ne!(rule.severity(), "unknown", "{} lacks severity", rule.id);
        assert!(
            rule.meta.contains_key("log_type"),
            "{} lacks log_type",
            rule.id
        );
    }
}

/// Shipped CloudTrail rules that fire for one event.
fn cloudtrail_hits(set: &RuleSet, event: &NormalizedEvent) -> Vec<String> {
    set.for_log_type("cloudtrail")
        .filter(|r| rule::evaluate(r, event).is_some())
        .map(|r| r.id.clone())
        .collect()
}

fn fired(hits: &[String], id: &str) -> bool {
    hits.iter().any(|h| h == id)
}

/// A console sign-in whose recorded outcome is `outcome`; `None` writes the
/// JSON null CloudTrail uses when it has nothing to report.
fn console_login(identity: &str, outcome: Option<&str>) -> NormalizedEvent {
    let mut e = event("ConsoleLogin", identity);
    e.response = Some(match outcome {
        Some(value) => format!(r#"{{"ConsoleLogin":"{value}"}}"#),
        None => r#"{"ConsoleLogin":null}"#.to_owned(),
    });
    e
}

fn iam_policy_event(name: &str, policy_arn: Option<&str>) -> NormalizedEvent {
    let mut e = event(name, "IAMUser");
    e.event_source = Some("iam.amazonaws.com".into());
    e.request = Some(match policy_arn {
        Some(arn) => format!(r#"{{"userName":"dev","policyArn":"{arn}"}}"#),
        None => r#"{"userName":"dev"}"#.to_owned(),
    });
    e
}

#[test]
fn root_sign_in_attempts_and_confirmed_root_sign_ins_are_distinct_findings() {
    let set = RuleSet::shipped();

    let failed = cloudtrail_hits(&set, &console_login("Root", Some("Failure")));
    assert!(fired(&failed, "cloudtrail_root_console_login"));
    assert!(
        !fired(&failed, "cloudtrail_root_console_login_success"),
        "a rejected sign-in must not be reported as a root session"
    );

    let succeeded = cloudtrail_hits(&set, &console_login("Root", Some("Success")));
    assert!(fired(&succeeded, "cloudtrail_root_console_login"));
    assert!(fired(&succeeded, "cloudtrail_root_console_login_success"));

    // Someone else's successful sign-in is not a root sign-in.
    let iam_user = cloudtrail_hits(&set, &console_login("IAMUser", Some("Success")));
    assert!(!fired(&iam_user, "cloudtrail_root_console_login"));
    assert!(!fired(&iam_user, "cloudtrail_root_console_login_success"));
}

#[test]
fn a_confirmed_sign_in_needs_a_recorded_success() {
    let set = RuleSet::shipped();
    let mut absent = console_login("Root", Some("Success"));
    absent.response = None;

    for event in [
        absent,                                 // the outcome was never recorded
        console_login("Root", None),            // recorded, but null
        console_login("Root", Some("Failure")), // recorded as rejected
    ] {
        let hits = cloudtrail_hits(&set, &event);
        // The attempt still stands; only the confirmation is withheld.
        assert!(fired(&hits, "cloudtrail_root_console_login"));
        assert!(fired(&hits, "cloudtrail_login_without_mfa"));
        assert!(
            !fired(&hits, "cloudtrail_root_console_login_success"),
            "{:?} claimed a root session",
            event.response
        );
        assert!(
            !fired(&hits, "cloudtrail_login_without_mfa_success"),
            "{:?} claimed an MFA-less session",
            event.response
        );
    }
}

#[test]
fn sign_in_rules_only_read_the_sign_in_service() {
    let set = RuleSet::shipped();
    // `ConsoleLogin` reached from another service is not a console sign-in.
    let mut elsewhere = console_login("Root", Some("Success"));
    elsewhere.event_source = Some("iam.amazonaws.com".into());

    let hits = cloudtrail_hits(&set, &elsewhere);

    for id in [
        "cloudtrail_root_console_login",
        "cloudtrail_root_console_login_success",
        "cloudtrail_login_without_mfa",
        "cloudtrail_login_without_mfa_success",
    ] {
        assert!(!fired(&hits, id), "{id} fired off the sign-in source");
    }
}

#[test]
fn an_unknown_mfa_state_is_not_a_sign_in_without_mfa() {
    let set = RuleSet::shipped();
    let known_false = console_login("IAMUser", Some("Success"));
    let mut unknown = known_false.clone();
    unknown.mfa_authenticated = None;
    let mut with_mfa = known_false.clone();
    with_mfa.mfa_authenticated = Some(true);

    let false_hits = cloudtrail_hits(&set, &known_false);
    assert!(fired(&false_hits, "cloudtrail_login_without_mfa"));
    assert!(fired(&false_hits, "cloudtrail_login_without_mfa_success"));

    for event in [unknown, with_mfa] {
        let hits = cloudtrail_hits(&set, &event);
        assert!(
            !fired(&hits, "cloudtrail_login_without_mfa"),
            "mfa {:?} reported as absent",
            event.mfa_authenticated
        );
        assert!(
            !fired(&hits, "cloudtrail_login_without_mfa_success"),
            "mfa {:?} reported as absent",
            event.mfa_authenticated
        );
    }
}

#[test]
fn attaching_aws_administrator_access_reports_only_the_admin_rule() {
    let set = RuleSet::shipped();

    for partition in ["aws", "aws-us-gov", "aws-cn"] {
        let arn = format!("arn:{partition}:iam::aws:policy/AdministratorAccess");
        for name in ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"] {
            let hits = cloudtrail_hits(&set, &iam_policy_event(name, Some(&arn)));
            assert!(
                fired(&hits, "cloudtrail_admin_policy_attach_attempt"),
                "{name} {arn} was not called out as an admin grant"
            );
            assert!(
                !fired(&hits, "cloudtrail_iam_policy_change"),
                "{name} {arn} reported twice"
            );
        }
    }

    // A refused grant is still an attempt worth reporting.
    let mut denied = iam_policy_event(
        "AttachRolePolicy",
        Some("arn:aws:iam::aws:policy/AdministratorAccess"),
    );
    denied.error_code = Some("AccessDenied".into());
    assert!(fired(
        &cloudtrail_hits(&set, &denied),
        "cloudtrail_admin_policy_attach_attempt"
    ));
}

#[test]
fn every_other_policy_change_stays_with_the_generic_iam_rule() {
    let set = RuleSet::shipped();

    for (name, arn) in [
        // A managed policy that is not AdministratorAccess.
        (
            "AttachRolePolicy",
            Some("arn:aws:iam::aws:policy/ReadOnlyAccess"),
        ),
        // A customer-managed policy that merely borrows the name.
        (
            "AttachUserPolicy",
            Some("arn:aws:iam::000000000000:policy/AdministratorAccess"),
        ),
        // An attachment whose policy the log never recorded.
        ("AttachGroupPolicy", None),
        // An inline policy: there is no arn to compare at all.
        ("PutUserPolicy", None),
        ("SetDefaultPolicyVersion", None),
    ] {
        let hits = cloudtrail_hits(&set, &iam_policy_event(name, arn));
        assert!(
            fired(&hits, "cloudtrail_iam_policy_change"),
            "{name} {arn:?} went unreported"
        );
        assert!(
            !fired(&hits, "cloudtrail_admin_policy_attach_attempt"),
            "{name} {arn:?} was called an admin grant"
        );
    }
}

#[test]
fn streaming_rules_respect_each_events_log_type() {
    let set = RuleSet::from_source(
        r#"
rule cloudtrail_get {
    meta: log_type = "cloudtrail"
    fields: $method = event_name == "GET"
    condition: $method
}
rule alb_get {
    meta: log_type = "alb_access"
    fields: $method = event_name == "GET"
    condition: $method
}
"#,
    )
    .unwrap();
    let event = event("GET", "none");
    let mut streamer = rule::MatchStreamer::new(&set, 100);
    let mut hits = Vec::new();
    let mut sink = |batch: &[(String, rule::Hit)]| {
        hits.extend(batch.iter().map(|(rule_id, _)| rule_id.clone()));
        Ok::<_, std::convert::Infallible>(())
    };

    streamer.push_for_log_type(7, "alb_access", &event, &mut sink);
    let summary = streamer.finish(&mut sink).unwrap();

    assert_eq!(hits, ["alb_get"]);
    assert_eq!(summary.total, 1);
    assert_eq!(summary.unmatched, 0);
}

#[test]
fn user_rules_override_shipped_rules_with_the_same_id() {
    let tmp = tempfile::tempdir().unwrap();
    let user_dir = tmp.path().join("rules");
    write(
        &user_dir.join("alb_server_error.yar"),
        br#"rule alb_server_error {
               meta: description = "tuned" severity = "low" log_type = "alb_access"
               fields: $a = event_name == "GET"
               condition: $a
           }"#,
    );

    let set = RuleSet::load_layered(&user_dir).unwrap();

    assert_eq!(
        set.rules().len(),
        RuleSet::shipped().rules().len(),
        "the id is replaced, not duplicated"
    );
    let rule = set.rule("alb_server_error").unwrap();
    assert_eq!(rule.severity(), "low");
    assert_eq!(rule.description(), "tuned");
    assert!(set.is_user("alb_server_error"));
}

#[test]
fn user_rules_with_new_ids_are_added() {
    let tmp = tempfile::tempdir().unwrap();
    let user_dir = tmp.path().join("rules");
    write(
        &user_dir.join("extra.yar"),
        br#"rule my_rule { fields: $a = event_name == "AssumeRole" condition: $a }"#,
    );

    let set = RuleSet::load_layered(&user_dir).unwrap();

    assert_eq!(set.rules().len(), RuleSet::shipped().rules().len() + 1);
    assert!(set.rule("my_rule").is_some());
    assert!(set.rule("alb_server_error").is_some());
    // Absent user directory: the shipped pack alone.
    let plain = RuleSet::load_layered(&tmp.path().join("missing")).unwrap();
    assert_eq!(plain.rules().len(), RuleSet::shipped().rules().len());
}

#[test]
fn snapshot_writes_shipped_and_user_rules_into_the_case_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let user_dir = tmp.path().join("rules");
    write(&user_dir.join("mine.yar"), GOOD.as_bytes());
    let case_rules = tmp.path().join("case/rules");

    RuleSet::snapshot_into(&user_dir, &case_rules).unwrap();

    // The shipped pack comes out of the binary, not from a directory.
    assert!(case_rules.join("alb.yar").is_file());
    assert_eq!(
        RuleSet::load_dir(&case_rules).unwrap().rules().len(),
        RuleSet::shipped().rules().len() + 1
    );
    // User files are prefixed so they cannot overwrite a shipped file.
    assert!(case_rules.join("user-mine.yar").is_file());
}

#[test]
fn snapshot_drops_rules_that_are_no_longer_loaded() {
    let tmp = tempfile::tempdir().unwrap();
    let user_dir = tmp.path().join("rules");
    write(&user_dir.join("mine.yar"), GOOD.as_bytes());
    let case_rules = tmp.path().join("case/rules");
    let with_user = RuleSet::snapshot_into(&user_dir, &case_rules).unwrap();

    std::fs::remove_file(user_dir.join("mine.yar")).unwrap();
    let without_user = RuleSet::snapshot_into(&user_dir, &case_rules).unwrap();

    // The snapshot explains a result. A leftover file would claim a deleted
    // rule contributed to matches it no longer produced.
    assert_eq!(without_user, with_user - 1);
    assert!(case_rules.join("alb.yar").is_file());
    assert!(!case_rules.join("user-mine.yar").exists());
}

#[cfg(unix)]
#[test]
fn streaming_evaluation_memory_does_not_scale_with_event_count() {
    // The whole point of MatchStreamer: neither events nor hits accumulate.
    // Tripling the event count must not triple the footprint (NFR-2).
    let small = evaluate_n(20_000);
    let large = evaluate_n(60_000);

    assert!(
        large < small * 2,
        "peak growth scaled with input: {small} -> {large} bytes"
    );
}

#[cfg(unix)]
fn evaluate_n(count: usize) -> u64 {
    let set = RuleSet::from_source(GOOD).unwrap();
    let events: Vec<_> = (0..count).map(|_| event("ConsoleLogin", "Root")).collect();

    let before = peak_rss();
    let mut sunk = 0u64;
    let mut sink = |batch: &[awslog_core::rule::Hit]| -> Result<(), String> {
        sunk += batch.len() as u64;
        Ok(())
    };
    let mut streamer = awslog_core::rule::MatchStreamer::new(&set, 1_000);
    for (i, e) in events.iter().enumerate() {
        streamer.push(i as u64, e, &mut |batch| {
            sink(&batch.iter().map(|(_, h)| h.clone()).collect::<Vec<_>>())
        });
    }
    let summary = streamer
        .finish(&mut |batch| sink(&batch.iter().map(|(_, h)| h.clone()).collect::<Vec<_>>()))
        .unwrap();

    assert_eq!(summary.total, count as u64);
    assert_eq!(sunk, count as u64);
    peak_rss().saturating_sub(before)
}

#[cfg(target_os = "macos")]
fn peak_rss() -> u64 {
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
