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
    assert_eq!(set.for_log_type("cloudtrail").count(), 11);
    assert_eq!(set.for_log_type("alb_access").count(), 3);
    assert_eq!(set.for_log_type("waf_acl").count(), 2);
    assert_eq!(set.for_log_type("apigw_access").count(), 1);
    assert_eq!(set.for_log_type("nginx_access").count(), 1);

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
