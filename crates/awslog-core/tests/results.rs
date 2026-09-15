//! Results view queries (docs/04 "결과 뷰 모델", FR-6).

mod support;

use awslog_core::model::NormalizedEvent;
use awslog_core::results::{self, Window};
use awslog_core::rule::{Hit, RuleSet};
use awslog_core::store::Store;
use std::collections::BTreeMap;
use time::macros::datetime;

fn event(id: u64, name: &str) -> NormalizedEvent {
    NormalizedEvent {
        file_id: 0,
        record_index: id,
        event_time: None,
        event_source: Some("signin.amazonaws.com".into()),
        event_name: Some(name.into()),
        aws_region: Some("ap-northeast-2".into()),
        account_id: None,
        source_ip: Some("203.0.113.10".into()),
        user_agent: None,
        identity_type: Some("Root".into()),
        identity_arn: Some("arn:aws:iam::000000000000:root".into()),
        identity_name: None,
        mfa_authenticated: Some(false),
        error_code: None,
        error_message: None,
        read_only: Some(false),
        management_event: Some(true),
        request: None,
        response: None,
        resources: None,
        raw: Some(format!(r#"{{"eventName":"{name}","seq":{id}}}"#)),
    }
}

/// A store with `count` matching events already evaluated.
fn seeded(count: u64) -> (tempfile::TempDir, Store, RuleSet) {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();

    let events: Vec<_> = (0..count).map(|i| event(i, "ConsoleLogin")).collect();
    store.append_events(&events).unwrap();

    let set = RuleSet::from_source(
        r#"rule root_login {
               meta: name = "루트 콘솔 로그인" description = "Root console login" severity = "high"
               fields: $name = event_name == "ConsoleLogin"
                       $root = identity_type == "Root"
               condition: $name and $root
           }"#,
    )
    .unwrap();
    let mut writer = store.writer_handle().unwrap();
    writer.begin_rule_run(set.rules()).unwrap();
    let mut sink = |batch: &[(String, Hit)]| writer.append_match_batch(batch);
    let mut streamer = awslog_core::rule::MatchStreamer::new(&set, 100);
    store
        .for_each_typed_event(|id, log_type, e| {
            streamer.push_for_log_type(id, log_type, &e, &mut sink)
        })
        .unwrap();
    streamer.finish(&mut sink).unwrap();

    (tmp, store, set)
}

#[test]
fn groups_results_by_rule_with_counts() {
    let (_tmp, store, _set) = seeded(30);

    let page = results::query(&store, &Window::default()).unwrap();

    assert_eq!(page.groups.len(), 1);
    let group = &page.groups[0];
    assert_eq!(group.rule_id, "root_login");
    assert_eq!(group.name, "루트 콘솔 로그인");
    assert_eq!(group.severity, "high");
    assert_eq!(group.description, "Root console login");
    assert_eq!(group.match_count, 30);
}

#[test]
fn paginates_matches_within_a_rule() {
    let (_tmp, store, _set) = seeded(250);

    let first = results::rule_matches(
        &store,
        "root_login",
        &Window {
            offset: 0,
            limit: 100,
            ..Default::default()
        },
    )
    .unwrap();
    let second = results::rule_matches(
        &store,
        "root_login",
        &Window {
            offset: 100,
            limit: 100,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(first.rows.len(), 100);
    assert_eq!(second.rows.len(), 100);
    // Pages must not overlap; the UI would show duplicates.
    assert_ne!(first.rows[0].event_id, second.rows[0].event_id);
    assert_eq!(first.total, 250);
}

#[test]
fn a_match_row_carries_the_evidence_and_a_summary() {
    let (_tmp, store, _set) = seeded(5);

    let page = results::rule_matches(
        &store,
        "root_login",
        &Window {
            offset: 0,
            limit: 10,
            ..Default::default()
        },
    )
    .unwrap();

    let row = &page.rows[0];
    assert_eq!(row.event_name.as_deref(), Some("ConsoleLogin"));
    assert_eq!(row.source_ip.as_deref(), Some("203.0.113.10"));
    // Evidence travels with the row so the view never re-evaluates (docs/04).
    let fields: BTreeMap<String, String> = serde_json::from_str(&row.matched_fields).unwrap();
    assert_eq!(fields.get("$root").map(String::as_str), Some("Root"));
}

#[test]
fn unmatched_count_accounts_for_every_event() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    store
        .append_events(&[event(0, "ConsoleLogin"), event(1, "AssumeRole")])
        .unwrap();

    let set = RuleSet::from_source(
        r#"rule only_console { fields: $a = event_name == "ConsoleLogin" condition: $a }"#,
    )
    .unwrap();
    let mut writer = store.writer_handle().unwrap();
    writer.begin_rule_run(set.rules()).unwrap();
    let mut sink = |batch: &[(String, Hit)]| writer.append_match_batch(batch);
    let mut streamer = awslog_core::rule::MatchStreamer::new(&set, 10);
    store
        .for_each_typed_event(|id, log_type, e| {
            streamer.push_for_log_type(id, log_type, &e, &mut sink)
        })
        .unwrap();
    streamer.finish(&mut sink).unwrap();

    let page = results::query(&store, &Window::default()).unwrap();

    assert_eq!(page.total_events, 2);
    assert_eq!(page.matched_events, 1);
    assert_eq!(page.unmatched_events, 1);
}

#[test]
fn match_rows_carry_their_log_type_and_alb_summary_columns() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    store.register_file(1, "b.log.gz", 1, "alb_access").unwrap();
    let mut alb = event(0, "GET");
    alb.file_id = 1;
    alb.request = Some(r#"{"method":"GET","url":"https://example.test/login"}"#.into());
    alb.response = Some(r#"{"elb_status_code":503,"target_status_code":null}"#.into());
    alb.resources = Some(r#"{"load_balancer":"app/x","target":"10.0.0.5:8080"}"#.into());
    let mut trail = event(0, "GetObject");
    trail.aws_region = Some("ap-northeast-2".into());
    trail.error_code = Some("AccessDenied".into());
    trail.resources =
        Some(r#"[{"ARN":"arn:aws:s3:::bucket/key","type":"AWS::S3::Object"}]"#.into());
    store.append_events(&[trail, alb]).unwrap();

    let page = results::all_events(
        &store,
        &results::Window {
            limit: 10,
            ..Default::default()
        },
    )
    .unwrap();

    let trail = page
        .rows
        .iter()
        .find(|r| r.log_type == "cloudtrail")
        .unwrap();
    assert_eq!(trail.event_name.as_deref(), Some("GetObject"));
    assert!(trail.url.is_none() && trail.status.is_none() && trail.target.is_none());
    assert_eq!(trail.aws_region.as_deref(), Some("ap-northeast-2"));
    assert_eq!(trail.error_code.as_deref(), Some("AccessDenied"));
    assert_eq!(trail.resource.as_deref(), Some("arn:aws:s3:::bucket/key"));
    let alb = page
        .rows
        .iter()
        .find(|r| r.log_type == "alb_access")
        .unwrap();
    assert_eq!(alb.url.as_deref(), Some("https://example.test/login"));
    assert_eq!(alb.status.as_deref(), Some("503"));
    assert_eq!(alb.target.as_deref(), Some("10.0.0.5:8080"));
    assert!(
        alb.resource.is_none(),
        "ALB resources is an object, not an ARN list"
    );
}

#[test]
fn rules_are_registered_unevaluated_and_evaluated_one_at_a_time() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    store.register_file(1, "b.log.gz", 1, "alb_access").unwrap();
    let mut alb = event(5, "GET");
    alb.file_id = 1;
    store
        .append_events(&[event(0, "ConsoleLogin"), event(1, "AssumeRole"), alb])
        .unwrap();
    let set = RuleSet::from_source(
        r#"rule login {
               meta: log_type = "cloudtrail"
               fields: $n = event_name == "ConsoleLogin" condition: $n
           }
           rule fail {
               meta: log_type = "cloudtrail"
               fields: $f = response.ConsoleLogin == "Failure" condition: $f
           }
           rule get { fields: $n = event_name == "GET" condition: $n }"#,
    )
    .unwrap();

    // Registration alone: listed, unevaluated, no matches.
    store
        .writer_handle()
        .unwrap()
        .begin_rule_run(set.rules())
        .unwrap();
    let page = results::query(&store, &Window::default()).unwrap();
    assert_eq!(page.groups.len(), 3);
    assert!(page
        .groups
        .iter()
        .all(|g| !g.evaluated && g.match_count == 0));
    assert_eq!(page.matched_events, 0);

    // One rule evaluated; the others stay pending.
    let hits = results::evaluate_rule(&mut store, set.rule("login").unwrap()).unwrap();
    assert_eq!(hits, 1);
    let page = results::query(&store, &Window::default()).unwrap();
    let login = page.groups.iter().find(|g| g.rule_id == "login").unwrap();
    assert!(login.evaluated);
    assert_eq!(login.match_count, 1);
    assert!(page
        .groups
        .iter()
        .filter(|g| g.rule_id != "login")
        .all(|g| !g.evaluated));
    assert_eq!(page.matched_events, 1);

    // Only the columns a rule names are read; a JSON-path rule still sees
    // its column. `seeded()` events carry no response, so use `get`.
    assert_eq!(
        results::evaluate_rule(&mut store, set.rule("fail").unwrap()).unwrap(),
        0
    );
    // An unscoped rule sees every file; match ids continue past `login`'s.
    assert_eq!(
        results::evaluate_rule(&mut store, set.rule("get").unwrap()).unwrap(),
        1
    );
    assert_eq!(store.matched_event_count(&Default::default()).unwrap(), 2);

    // Re-evaluating replaces, never duplicates.
    results::evaluate_rule(&mut store, set.rule("login").unwrap()).unwrap();
    let page = results::query(&store, &Window::default()).unwrap();
    assert_eq!(
        page.groups
            .iter()
            .find(|g| g.rule_id == "login")
            .unwrap()
            .match_count,
        1
    );

    // A saved rule comes back pending; a removed rule is gone from the case.
    store.reset_rule(set.rule("login").unwrap()).unwrap();
    store.remove_rule("get").unwrap();
    let page = results::query(&store, &Window::default()).unwrap();
    let ids: Vec<_> = page
        .groups
        .iter()
        .map(|g| (g.rule_id.as_str(), g.evaluated, g.match_count))
        .collect();
    assert!(ids.contains(&("login", false, 0)));
    assert!(!ids.iter().any(|(id, _, _)| *id == "get"));
    assert_eq!(page.matched_events, 0);
}

#[test]
fn evaluating_a_json_path_rule_reads_its_column() {
    // Column projection must include `response` for `response.X` fields.
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    let mut failed = event(0, "ConsoleLogin");
    failed.response = Some(r#"{"ConsoleLogin":"Failure"}"#.into());
    store
        .append_events(&[failed, event(1, "ConsoleLogin")])
        .unwrap();
    let set = RuleSet::from_source(
        r#"rule fail { fields: $f = response.ConsoleLogin == "Failure" condition: $f }"#,
    )
    .unwrap();
    store
        .writer_handle()
        .unwrap()
        .begin_rule_run(set.rules())
        .unwrap();

    assert_eq!(
        results::evaluate_rule(&mut store, set.rule("fail").unwrap()).unwrap(),
        1
    );
}

#[test]
fn log_type_filter_narrows_events_groups_and_matches() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    store.register_file(1, "b.log.gz", 1, "alb_access").unwrap();
    let mut alb = event(0, "GET");
    alb.file_id = 1;
    let mut alb2 = event(1, "GET");
    alb2.file_id = 1;
    store
        .append_events(&[
            event(0, "ConsoleLogin"),
            event(1, "ConsoleLogin"),
            alb,
            alb2,
        ])
        .unwrap();

    // One rule per type plus one unscoped rule that fires on both.
    let set = RuleSet::from_source(
        r#"rule trail_login {
               meta: log_type = "cloudtrail"
               fields: $n = event_name == "ConsoleLogin" condition: $n
           }
           rule alb_get {
               meta: log_type = "alb_access"
               fields: $n = event_name == "GET" condition: $n
           }
           rule any_root {
               fields: $r = identity_type == "Root" condition: $r
           }"#,
    )
    .unwrap();
    let mut writer = store.writer_handle().unwrap();
    writer.begin_rule_run(set.rules()).unwrap();
    let mut sink = |batch: &[(String, Hit)]| writer.append_match_batch(batch);
    let mut streamer = awslog_core::rule::MatchStreamer::new(&set, 10);
    store
        .for_each_typed_event(|id, log_type, e| {
            streamer.push_for_log_type(id, log_type, &e, &mut sink)
        })
        .unwrap();
    streamer.finish(&mut sink).unwrap();

    let all = results::query(&store, &Window::default()).unwrap();
    let mut types: Vec<_> = all
        .log_types
        .iter()
        .map(|t| (t.log_type.as_str(), t.events))
        .collect();
    types.sort();
    assert_eq!(types, [("alb_access", 2), ("cloudtrail", 2)]);
    assert_eq!(all.groups.len(), 3);

    let window = Window {
        limit: 10,
        log_type: Some("alb_access".into()),
        ..Default::default()
    };
    let alb_page = results::query(&store, &window).unwrap();

    assert_eq!(alb_page.total_events, 2);
    assert_eq!(alb_page.matched_events, 2);
    // The cloudtrail-only rule is not listed; the unscoped rule counts only
    // this type's events.
    let mut groups: Vec<_> = alb_page
        .groups
        .iter()
        .map(|g| (g.rule_id.as_str(), g.match_count))
        .collect();
    groups.sort();
    assert_eq!(groups, [("alb_get", 2), ("any_root", 2)]);
    let alb_matches = results::rule_matches(&store, "any_root", &window).unwrap();
    assert_eq!(alb_matches.total, 2);
    assert!(alb_matches
        .rows
        .iter()
        .all(|m| m.event_name.as_deref() == Some("GET")));

    let events = results::all_events(&store, &window).unwrap();
    assert_eq!(events.total, 2);
    assert!(events
        .rows
        .iter()
        .all(|m| m.event_name.as_deref() == Some("GET")));
}

#[test]
fn reopening_an_older_case_adds_the_rule_log_type_column() {
    // Cases created before `rules.log_type` existed must still record a
    // rule run after reopening.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("s.duckdb");
    {
        let conn = duckdb::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE rules (rule_id VARCHAR PRIMARY KEY, severity VARCHAR NOT NULL,
                                 description VARCHAR NOT NULL);
             CREATE TABLE rule_matches (match_id UBIGINT PRIMARY KEY, rule_id VARCHAR NOT NULL,
                                        event_id UBIGINT NOT NULL, matched_fields JSON NOT NULL);",
        )
        .unwrap();
    }
    let store = Store::open(&db).unwrap();
    let set = RuleSet::from_source(
        r#"rule alb_get { meta: log_type = "alb_access" fields: $n = event_name == "GET" condition: $n }"#,
    )
    .unwrap();

    store
        .writer_handle()
        .unwrap()
        .begin_rule_run(set.rules())
        .unwrap();

    // The scope was stored in the migrated column; the rule is not listed
    // because this case holds no ALB events.
    assert!(!store.rules_lack_log_type().unwrap());
    assert!(results::query(&store, &Window::default())
        .unwrap()
        .groups
        .is_empty());
}

#[test]
fn a_rule_registered_before_the_name_column_is_listed_under_its_id() {
    // Cases hold rule rows written by older builds; the sidebar shows the
    // name alone, so an absent one must read as the id, not as nothing.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("s.duckdb");
    {
        let conn = duckdb::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE rules (rule_id VARCHAR PRIMARY KEY, severity VARCHAR NOT NULL,
                                 description VARCHAR NOT NULL, log_type VARCHAR,
                                 evaluated BOOLEAN DEFAULT true);
             INSERT INTO rules VALUES ('old_rule', 'low', 'from an older build', NULL, true);",
        )
        .unwrap();
    }
    let store = Store::open(&db).unwrap();

    let page = results::query(&store, &Window::default()).unwrap();

    assert_eq!(page.groups.len(), 1);
    assert_eq!(page.groups[0].name, "old_rule");
}

#[test]
fn rule_names_are_backfilled_from_the_current_rules_without_reevaluating() {
    // The label is display data: an older case may take it from today's rule
    // pack. Only `meta: name` fills a gap — a rule without one must not pin
    // its id into the column and block a better source later.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("s.duckdb");
    {
        let conn = duckdb::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE rules (rule_id VARCHAR PRIMARY KEY, severity VARCHAR NOT NULL,
                                 description VARCHAR NOT NULL, log_type VARCHAR,
                                 evaluated BOOLEAN DEFAULT true);
             INSERT INTO rules VALUES ('named', 'low', 'x', NULL, true),
                                      ('nameless', 'low', 'y', NULL, true);",
        )
        .unwrap();
    }
    let mut store = Store::open(&db).unwrap();
    assert!(store.rules_lack_name().unwrap());
    let set = RuleSet::from_source(
        r#"rule named { meta: name = "이름 있음" fields: $n = event_name == "a" condition: $n }
           rule nameless { fields: $n = event_name == "b" condition: $n }"#,
    )
    .unwrap();

    store.backfill_rule_names(set.rules()).unwrap();

    let page = results::query(&store, &Window::default()).unwrap();
    let name = |id: &str| {
        page.groups
            .iter()
            .find(|g| g.rule_id == id)
            .unwrap()
            .name
            .clone()
    };
    assert_eq!(name("named"), "이름 있음");
    assert_eq!(name("nameless"), "nameless");
    assert!(store.rules_lack_name().unwrap());
}

#[test]
fn a_rules_page_is_served_from_the_match_table_alone() {
    // Paging a rule must not join the event table: on a 300M-row case that
    // was a full probe per page. Everything the table shows is copied into
    // the match row when the hit is recorded — so the page, its count, its
    // scope and its search all survive the events being gone.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("s.duckdb");
    let set =
        RuleSet::from_source(r#"rule everything { fields: $n = event_name exists condition: $n }"#)
            .unwrap();
    {
        let mut store = Store::create(&db, "c1", "/logs").unwrap();
        store
            .register_file(0, "a.json.gz", 1, "cloudtrail")
            .unwrap();
        store.register_file(1, "b.log.gz", 1, "alb_access").unwrap();
        let mut trail = event(0, "GetObject");
        trail.error_code = Some("AccessDenied".into());
        trail.resources =
            Some(r#"[{"ARN":"arn:aws:s3:::bucket/key","type":"AWS::S3::Object"}]"#.into());
        trail.event_time = Some(datetime!(2026-09-12 00:00:00).assume_utc());
        let mut alb = event(0, "GET");
        alb.file_id = 1;
        alb.request = Some(r#"{"method":"GET","url":"https://example.test/login"}"#.into());
        alb.response = Some(r#"{"elb_status_code":503}"#.into());
        alb.resources = Some(r#"{"target":"10.0.0.5:8080"}"#.into());
        alb.event_time = Some(datetime!(2026-09-13 00:00:00).assume_utc());
        store.append_events(&[trail, alb]).unwrap();
        store.begin_rule_run(set.rules()).unwrap();
        results::evaluate_rule(&mut store, set.rule("everything").unwrap()).unwrap();
    }
    duckdb::Connection::open(&db)
        .unwrap()
        .execute_batch("DELETE FROM events")
        .unwrap();
    let store = Store::open(&db).unwrap();

    let ten = Window {
        limit: 10,
        ..Default::default()
    };
    let page = results::rule_matches(&store, "everything", &ten).unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(page.rows.len(), 2);
    let trail = &page.rows[0];
    assert_eq!(trail.log_type, "cloudtrail");
    assert_eq!(trail.event_time.as_deref(), Some("2026-09-12 09:00:00.000"));
    assert_eq!(trail.event_name.as_deref(), Some("GetObject"));
    assert_eq!(trail.error_code.as_deref(), Some("AccessDenied"));
    assert_eq!(trail.resource.as_deref(), Some("arn:aws:s3:::bucket/key"));
    assert!(trail.url.is_none());
    let alb = &page.rows[1];
    assert_eq!(alb.log_type, "alb_access");
    assert_eq!(alb.url.as_deref(), Some("https://example.test/login"));
    assert_eq!(alb.status.as_deref(), Some("503"));
    assert_eq!(alb.target.as_deref(), Some("10.0.0.5:8080"));
    assert_eq!(alb.method.as_deref(), Some("GET"));

    let alb_only = Window {
        log_type: Some("alb_access".into()),
        ..Default::default()
    };
    assert_eq!(
        results::rule_matches(&store, "everything", &alb_only)
            .unwrap()
            .total,
        1
    );
    assert_eq!(
        results::query(&store, &alb_only).unwrap().groups[0].match_count,
        1
    );
    let on_the_12th = Window {
        from: Some("2026-09-12".into()),
        to: Some("2026-09-12".into()),
        ..Default::default()
    };
    assert_eq!(
        results::rule_matches(&store, "everything", &on_the_12th)
            .unwrap()
            .total,
        1
    );
    let searched = Window {
        search: "getobject".into(),
        ..Default::default()
    };
    assert_eq!(
        results::rule_matches(&store, "everything", &searched)
            .unwrap()
            .total,
        1
    );
}

#[test]
fn an_older_case_gets_its_match_summaries_rebuilt_on_open() {
    // Hits recorded before the summary columns existed are kept: the
    // summaries are fetched once on open, by event id, instead of running
    // every rule again over the whole case.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("s.duckdb");
    {
        let mut store = Store::create(&db, "c1", "/logs").unwrap();
        store
            .register_file(0, "a.json.gz", 1, "cloudtrail")
            .unwrap();
        store.register_file(1, "b.log.gz", 1, "alb_access").unwrap();
        let mut alb = event(0, "GET");
        alb.file_id = 1;
        alb.request = Some(r#"{"method":"GET","url":"https://example.test/login"}"#.into());
        store
            .append_events(&[event(0, "GetObject"), event(1, "PutObject"), alb])
            .unwrap();
    }
    duckdb::Connection::open(&db)
        .unwrap()
        .execute_batch(
            "DROP TABLE rule_matches;
             CREATE TABLE rule_matches (match_id UBIGINT PRIMARY KEY, rule_id VARCHAR NOT NULL,
                                        event_id UBIGINT NOT NULL, matched_fields JSON NOT NULL);
             INSERT INTO rule_matches VALUES
                 (0, 'everything', 0, '{\"$n\": \"GetObject\"}'),
                 (1, 'everything', 4294967296, '{}'),
                 (2, 'gets', 4294967296, '{}');
             INSERT INTO rules (rule_id, severity, description, log_type, evaluated)
                 VALUES ('everything', 'low', 'All', NULL, true),
                        ('gets', 'low', 'GETs', 'alb_access', true);",
        )
        .unwrap();

    let store = Store::open(&db).unwrap();

    let ten = Window {
        limit: 10,
        ..Default::default()
    };
    let page = results::rule_matches(&store, "everything", &ten).unwrap();
    assert_eq!(page.total, 2);
    let trail = page.rows.iter().find(|r| r.event_id == 0).unwrap();
    assert_eq!(trail.log_type, "cloudtrail");
    assert_eq!(trail.event_name.as_deref(), Some("GetObject"));
    let fields: BTreeMap<String, String> = serde_json::from_str(&trail.matched_fields).unwrap();
    assert_eq!(fields.get("$n").map(String::as_str), Some("GetObject"));
    let alb = page.rows.iter().find(|r| r.event_id == 1 << 32).unwrap();
    assert_eq!(alb.log_type, "alb_access");
    assert_eq!(alb.url.as_deref(), Some("https://example.test/login"));
    let groups = results::query(
        &store,
        &Window {
            log_type: Some("alb_access".into()),
            ..Default::default()
        },
    )
    .unwrap()
    .groups;
    let mut counts: Vec<_> = groups
        .iter()
        .map(|g| (g.rule_id.as_str(), g.match_count, g.evaluated))
        .collect();
    counts.sort();
    assert_eq!(counts, [("everything", 1, true), ("gets", 1, true)]);

    // A second open finds the new shape and leaves it alone.
    drop(store);
    let store = Store::open(&db).unwrap();
    assert_eq!(store.match_count().unwrap(), 3);
}

#[test]
fn a_match_migration_that_fails_midway_leaves_the_old_table_for_the_next_open() {
    // The refill runs in batches of 10,000. If it dies after the first
    // batch, nothing of it may persist: a new-shaped table holding half
    // the hits would pass the shape check on the next open and be served
    // as complete while the rules still read as evaluated.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("s.duckdb");
    {
        let mut store = Store::create(&db, "c1", "/logs").unwrap();
        store
            .register_file(0, "a.json.gz", 1, "cloudtrail")
            .unwrap();
        store.append_events(&[event(0, "GetObject")]).unwrap();
    }
    duckdb::Connection::open(&db)
        .unwrap()
        .execute_batch(
            "DROP TABLE rule_matches;
             CREATE TABLE rule_matches (match_id UBIGINT PRIMARY KEY, rule_id VARCHAR NOT NULL,
                                        event_id UBIGINT, matched_fields JSON NOT NULL);
             INSERT INTO rule_matches SELECT range, 'r', 0, '{}' FROM range(10000);
             INSERT INTO rule_matches VALUES (10000, 'r', NULL, '{}');
             INSERT INTO rules (rule_id, severity, description, log_type, evaluated)
                 VALUES ('r', 'low', 'R', NULL, true);",
        )
        .unwrap();

    // The NULL id is unreadable as a u64: the second batch fails after the
    // first was appended.
    assert!(Store::open(&db).is_err());

    let conn = duckdb::Connection::open(&db).unwrap();
    let old_shape: bool = conn
        .query_row(
            "SELECT count(*) = 0 FROM information_schema.columns
             WHERE table_name = 'rule_matches' AND column_name = 'log_type'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(old_shape, "the old table is back in place");
    conn.execute(
        "UPDATE rule_matches SET event_id = 0 WHERE event_id IS NULL",
        [],
    )
    .unwrap();
    drop(conn);

    let store = Store::open(&db).unwrap();
    assert_eq!(store.match_count().unwrap(), 10_001);
    assert_eq!(
        results::query(&store, &Window::default()).unwrap().groups[0].match_count,
        10_001
    );
}

#[test]
fn raw_record_is_fetched_one_at_a_time() {
    let (_tmp, store, _set) = seeded(3);

    let raw = results::raw_record(&store, 1).unwrap().expect("record");

    // The list never carries raw bodies; this is the explicit drill-down.
    assert!(raw.contains("\"seq\":1"));
    assert!(results::raw_record(&store, 999).unwrap().is_none());
}

#[test]
fn querying_a_case_without_matches_returns_empty_groups_not_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();

    let page = results::query(&store, &Window::default()).unwrap();

    assert!(page.groups.is_empty());
    assert_eq!(page.total_events, 0);
}

#[test]
fn a_rule_run_records_metadata_so_severity_never_degrades() {
    // Regression: recording metadata used to be a separate call an evaluator
    // could forget, which silently produced `unknown` severity.
    let (_tmp, store, _set) = seeded(2);

    let page = results::query(&store, &Window::default()).unwrap();

    assert_eq!(page.groups[0].severity, "high");
    assert_eq!(page.groups[0].description, "Root console login");
}

#[test]
fn a_rule_that_matched_nothing_is_still_listed() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    store.append_events(&[event(0, "ConsoleLogin")]).unwrap();

    let set = RuleSet::from_source(
        r#"rule hit {
               meta: description = "Matches" severity = "high"
               fields: $n = event_name == "ConsoleLogin"
               condition: $n
           }
           rule miss {
               meta: description = "Matches nothing here" severity = "low"
               fields: $n = event_name == "DeleteTrail"
               condition: $n
           }"#,
    )
    .unwrap();
    let mut writer = store.writer_handle().unwrap();
    writer.begin_rule_run(set.rules()).unwrap();
    let mut sink = |batch: &[(String, Hit)]| writer.append_match_batch(batch);
    let mut streamer = awslog_core::rule::MatchStreamer::new(&set, 100);
    store
        .for_each_typed_event(|id, log_type, e| {
            streamer.push_for_log_type(id, log_type, &e, &mut sink)
        })
        .unwrap();
    streamer.finish(&mut sink).unwrap();

    let page = results::query(&store, &Window::default()).unwrap();

    // A rule with no hits is coverage information: hiding it makes an
    // unexercised rule indistinguishable from one that was never loaded.
    let ids: Vec<_> = page.groups.iter().map(|g| g.rule_id.as_str()).collect();
    assert_eq!(ids, vec!["hit", "miss"]);
    let miss = page.groups.iter().find(|g| g.rule_id == "miss").unwrap();
    assert_eq!(miss.match_count, 0);
    assert_eq!(miss.severity, "low");
    assert_eq!(miss.description, "Matches nothing here");
    // No `meta: name`: the id is the name, never an empty label.
    assert_eq!(miss.name, "miss");
}

#[test]
fn all_events_can_be_paged_without_a_rule() {
    let (_tmp, store, _set) = seeded(5);

    let page = |offset, limit| {
        results::all_events(
            &store,
            &results::Window {
                offset,
                limit,
                ..Default::default()
            },
        )
        .unwrap()
    };
    let first = page(0, 2);
    let rest = page(2, 10);

    // The "every event" view is how an analyst checks what the rules missed.
    assert_eq!(first.rows.len(), 2);
    assert_eq!(rest.rows.len(), 3);
    assert_eq!(first.total, 5);
    assert_eq!(first.rows[0].event_name.as_deref(), Some("ConsoleLogin"));
    assert_eq!(first.rows[0].matched_fields, "{}");
}

#[test]
fn event_times_are_shown_in_kst_with_milliseconds() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    let mut e = event(0, "ConsoleLogin");
    // CloudTrail stores UTC; analysts here read KST, and sub-second order
    // matters when hundreds of events share a second.
    e.event_time = Some(
        time::OffsetDateTime::parse(
            "2026-08-30T23:51:52.481Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap(),
    );
    store.append_events(&[e]).unwrap();

    let page = results::all_events(
        &store,
        &results::Window {
            offset: 0,
            limit: 1,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(
        page.rows[0].event_time.as_deref(),
        Some("2026-08-31 08:51:52.481")
    );
}

#[test]
fn one_events_stored_columns_can_be_read_back() {
    let (_tmp, store, _set) = seeded(3);

    let fields = results::event_fields(&store, 1).unwrap();

    // The detail view must show what the rules matched on, which is the
    // stored row — not the raw record re-resolved with a newer mapping.
    let get = |key: &str| {
        fields
            .iter()
            .find(|(field, _)| field == key)
            .and_then(|(_, value)| value.clone())
    };
    assert_eq!(get("event_name").as_deref(), Some("ConsoleLogin"));
    assert_eq!(get("identity_type").as_deref(), Some("Root"));
    assert_eq!(get("aws_region").as_deref(), Some("ap-northeast-2"));
    assert_eq!(get("mfa_authenticated").as_deref(), Some("false"));
    // Absent columns are reported as absent, not as empty strings.
    assert_eq!(get("error_code"), None);
    assert_eq!(fields.len(), 18);
}

#[test]
fn reading_a_missing_event_yields_nothing() {
    let (_tmp, store, _set) = seeded(1);

    assert!(results::event_fields(&store, 999).unwrap().is_empty());
}

#[test]
fn a_rule_can_be_counted_without_saving_or_touching_stored_matches() {
    let (_tmp, store, _set) = seeded(4);
    let before = store.rule_groups(&Default::default()).unwrap();

    let count = results::count_matches(
        &store,
        &RuleSet::from_source(
            r#"rule trial {
                   meta: description = "d" severity = "low"
                   fields: $n = event_name == "ConsoleLogin"
                   condition: $n
               }"#,
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(count.hits, 4);
    // The proportion is read off one pass, so `scanned` is every event.
    assert_eq!(count.scanned, 4);
    // A dry run must not write: the author is still editing.
    assert_eq!(
        store.rule_groups(&Default::default()).unwrap().len(),
        before.len()
    );
    assert_eq!(store.matched_event_count(&Default::default()).unwrap(), 4);
}

#[test]
fn counting_a_rule_that_matches_nothing_returns_zero() {
    let (_tmp, store, _set) = seeded(2);

    let count = results::count_matches(
        &store,
        &RuleSet::from_source(
            r#"rule trial {
                   meta: description = "d" severity = "low"
                   fields: $n = event_name == "DeleteTrail"
                   condition: $n
               }"#,
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(count.hits, 0);
    assert_eq!(count.scanned, 2);
}

/// Events whose time order is the reverse of their insertion order, so a sort
/// that silently falls back to `event_id` cannot pass these tests.
fn timed() -> (tempfile::TempDir, Store) {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();

    let mut rows = Vec::new();
    for (i, (day, name, ip)) in [
        (13, "DeleteTrail", "198.51.100.7"),
        (12, "ConsoleLogin", "203.0.113.10"),
        (11, "CreateUser", "203.0.113.99"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut e = event(i as u64, name);
        e.event_time = Some(
            datetime!(2026-09-11 00:00:00)
                .assume_utc()
                .replace_day(day)
                .unwrap(),
        );
        e.source_ip = Some(ip.into());
        rows.push(e);
    }

    // A record whose time could not be parsed. It must never lead the
    // oldest-first list: the analyst reads that position as "first".
    let mut timeless = event(9, "StopLogging");
    timeless.event_time = None;
    timeless.source_ip = Some("192.0.2.1".into());
    rows.push(timeless);
    store.append_events(&rows).unwrap();

    let set = RuleSet::from_source(
        r#"rule everything {
               meta: description = "All events" severity = "low"
               fields: $any = event_name exists
               condition: $any
           }"#,
    )
    .unwrap();
    let mut writer = store.writer_handle().unwrap();
    writer.begin_rule_run(set.rules()).unwrap();
    let mut sink = |batch: &[(String, Hit)]| writer.append_match_batch(batch);
    let mut streamer = awslog_core::rule::MatchStreamer::new(&set, 100);
    store
        .for_each_typed_event(|id, log_type, e| {
            streamer.push_for_log_type(id, log_type, &e, &mut sink)
        })
        .unwrap();
    streamer.finish(&mut sink).unwrap();

    (tmp, store)
}

fn names(page: &results::EventPage) -> Vec<&str> {
    page.rows
        .iter()
        .map(|m| m.event_name.as_deref().unwrap_or("—"))
        .collect()
}

#[test]
fn a_rules_matches_are_ordered_oldest_first_unless_asked_otherwise() {
    let (_tmp, store) = timed();

    let oldest = results::rule_matches(
        &store,
        "everything",
        &Window {
            offset: 0,
            limit: 10,
            ..Default::default()
        },
    )
    .unwrap();
    let newest = results::rule_matches(
        &store,
        "everything",
        &Window {
            offset: 0,
            limit: 10,
            newest_first: true,
            ..Default::default()
        },
    )
    .unwrap();

    // Insertion order is DeleteTrail, ConsoleLogin, CreateUser — neither of
    // these orders, so the sort is reading the time column. The timeless
    // record sits last in both directions rather than jumping to the front
    // of whichever end DuckDB happens to put nulls at.
    assert_eq!(
        names(&oldest),
        ["CreateUser", "ConsoleLogin", "DeleteTrail", "StopLogging"]
    );
    assert_eq!(
        names(&newest),
        ["DeleteTrail", "ConsoleLogin", "CreateUser", "StopLogging"]
    );
}

#[test]
fn the_all_tab_lists_only_rules_for_parsed_log_types() {
    // A cloudtrail-only case: an ALB rule is loaded but can never fire, and
    // listing it would suggest ALB logs were analysed.
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    store.register_file(1, "b.log.gz", 1, "alb_access").unwrap();
    store.append_events(&[event(0, "ConsoleLogin")]).unwrap();
    let set = RuleSet::from_source(
        r#"rule trail { meta: log_type = "cloudtrail" fields: $n = event_name exists condition: $n }
           rule alb { meta: log_type = "alb_access" fields: $n = event_name exists condition: $n }
           rule any { fields: $n = event_name exists condition: $n }"#,
    )
    .unwrap();
    store
        .writer_handle()
        .unwrap()
        .begin_rule_run(set.rules())
        .unwrap();

    let page = results::query(&store, &Window::default()).unwrap();

    let mut ids: Vec<_> = page.groups.iter().map(|g| g.rule_id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, ["any", "trail"]);
}

#[test]
fn rule_log_types_can_be_backfilled_from_a_rule_set() {
    // Cases recorded before `rules.log_type` existed carry NULLs; the app
    // fills them from the case's rule snapshot instead of re-evaluating.
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    store.append_events(&[event(0, "ConsoleLogin")]).unwrap();
    let unscoped =
        RuleSet::from_source(r#"rule alb { fields: $n = event_name exists condition: $n }"#)
            .unwrap();
    store
        .writer_handle()
        .unwrap()
        .begin_rule_run(unscoped.rules())
        .unwrap();
    assert!(store.rules_lack_log_type().unwrap());
    assert_eq!(
        results::query(&store, &Window::default())
            .unwrap()
            .groups
            .len(),
        1
    );

    let scoped = RuleSet::from_source(
        r#"rule alb { meta: log_type = "alb_access" fields: $n = event_name exists condition: $n }"#,
    )
    .unwrap();
    store
        .writer_handle()
        .unwrap()
        .backfill_rule_log_types(scoped.rules())
        .unwrap();

    assert!(!store.rules_lack_log_type().unwrap());
    assert!(results::query(&store, &Window::default())
        .unwrap()
        .groups
        .is_empty());
}

#[test]
fn a_date_range_narrows_every_view_in_kst() {
    let (_tmp, store) = timed();
    // Events are at 00:00 UTC on the 11th–13th, i.e. 09:00 KST the same day.
    let window = results::Window {
        limit: 10,
        from: Some("2026-09-12".into()),
        to: Some("2026-09-12".into()),
        ..Default::default()
    };

    let matches = results::rule_matches(&store, "everything", &window).unwrap();
    assert_eq!(names(&matches), ["ConsoleLogin"]);
    assert_eq!(matches.total, 1);
    let page = results::query(&store, &window).unwrap();
    assert_eq!(page.groups[0].match_count, 1);
    // The timeless event is excluded: it cannot be placed in the range.
    assert_eq!(page.total_events, 1);
    assert_eq!(page.matched_events, 1);
    assert_eq!(page.first_day.as_deref(), Some("2026-09-11"));
    assert_eq!(page.last_day.as_deref(), Some("2026-09-13"));

    let events = results::all_events(&store, &window).unwrap();
    assert_eq!(events.total, 1);
    assert_eq!(events.rows[0].event_name.as_deref(), Some("ConsoleLogin"));

    // Open-ended: only a lower bound.
    let from_12 = results::all_events(
        &store,
        &results::Window {
            limit: 10,
            from: Some("2026-09-12".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(from_12.total, 2);

    // A KST day boundary: 2026-09-11 09:00 KST is inside the 11th, so a
    // range ending on the 10th excludes it and one ending on the 11th does not.
    let to_10 = results::all_events(
        &store,
        &results::Window {
            limit: 10,
            to: Some("2026-09-10".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(to_10.total, 0);
}

#[test]
fn backfill_never_overwrites_a_scope_already_restored() {
    // Snapshot first, bundled rules second: the snapshot says `alb_access`,
    // the bundled copy of the same rule says `cloudtrail`. The snapshot must
    // win, while a rule the snapshot left unscoped may still be filled.
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&tmp.path().join("s.duckdb"), "c1", "/logs").unwrap();
    let unscoped = RuleSet::from_source(
        r#"rule a { fields: $n = event_name exists condition: $n }
           rule b { fields: $n = event_name exists condition: $n }"#,
    )
    .unwrap();
    let mut writer = store.writer_handle().unwrap();
    writer.begin_rule_run(unscoped.rules()).unwrap();

    let snapshot = RuleSet::from_source(
        r#"rule a { meta: log_type = "alb_access" fields: $n = event_name exists condition: $n }
           rule b { fields: $n = event_name exists condition: $n }"#,
    )
    .unwrap();
    let bundled = RuleSet::from_source(
        r#"rule a { meta: log_type = "cloudtrail" fields: $n = event_name exists condition: $n }
           rule b { meta: log_type = "cloudtrail" fields: $n = event_name exists condition: $n }"#,
    )
    .unwrap();
    writer.backfill_rule_log_types(snapshot.rules()).unwrap();
    writer.backfill_rule_log_types(bundled.rules()).unwrap();

    // Only cloudtrail events exist, so the listing reveals each scope.
    store
        .register_file(0, "a.json.gz", 1, "cloudtrail")
        .unwrap();
    store.append_events(&[event(0, "ConsoleLogin")]).unwrap();
    let page = results::query(&store, &Window::default()).unwrap();
    let ids: Vec<_> = page.groups.iter().map(|g| g.rule_id.as_str()).collect();
    assert_eq!(ids, ["b"], "a kept alb_access; b took cloudtrail");
}

#[test]
fn bounds_accept_a_time_of_day_and_are_inclusive_at_their_unit() {
    let (_tmp, store) = timed();
    let count = |from: Option<&str>, to: Option<&str>| {
        results::all_events(
            &store,
            &results::Window {
                limit: 10,
                from: from.map(str::to_owned),
                to: to.map(str::to_owned),
                ..Default::default()
            },
        )
        .map(|p| p.total)
    };
    // ConsoleLogin is at 2026-09-12 09:00:00 KST exactly.
    assert_eq!(
        count(Some("2026-09-12 09:00:00"), Some("2026-09-12 09:00:00")).unwrap(),
        1
    );
    assert_eq!(
        count(Some("2026-09-12 09:00:01"), Some("2026-09-12")).unwrap(),
        0
    );
    assert_eq!(
        count(Some("2026-09-12"), Some("2026-09-12 08:59:59")).unwrap(),
        0
    );
    assert_eq!(
        count(Some("2026-09-12 09:00"), Some("2026-09-12 09:00")).unwrap(),
        1
    );
    assert_eq!(
        count(Some("2026-09-12 08:59"), Some("2026-09-12 08:59")).unwrap(),
        0
    );
    // Malformed input is an error the UI can show, not a silent full scan.
    assert!(matches!(
        count(Some("2026/09/12"), None),
        Err(awslog_core::store::StoreError::BadDateTime(_))
    ));
    assert!(count(Some("2026-09-12 25:00"), None).is_err());
}

#[test]
fn search_narrows_a_rules_matches_and_the_total_follows_the_filter() {
    let (_tmp, store) = timed();

    let window = Window {
        offset: 0,
        limit: 10,
        search: "console".into(),
        ..Default::default()
    };
    let page = results::rule_matches(&store, "everything", &window).unwrap();

    // Case-insensitive, and the count under the table must describe the
    // filtered list — not the rule's full hit count.
    assert_eq!(names(&page), ["ConsoleLogin"]);
    assert_eq!(page.total, 1);
    // The rule group keeps its real hit count: the sidebar is not filtered.
    assert_eq!(
        results::query(&store, &window).unwrap().groups[0].match_count,
        4
    );
}

#[test]
fn search_covers_every_column_the_table_shows() {
    let (_tmp, store) = timed();
    let hits = |needle: &str| {
        results::rule_matches(
            &store,
            "everything",
            &Window {
                offset: 0,
                limit: 10,
                search: needle.into(),
                ..Default::default()
            },
        )
        .unwrap()
        .total
    };

    assert_eq!(hits("198.51.100.7"), 1, "source ip");
    assert_eq!(hits("signin.amazonaws.com"), 4, "service");
    assert_eq!(hits(":root"), 4, "subject arn");
    // The displayed time is KST, so that is what a time search must match.
    assert_eq!(hits("2026-09-12 09:00"), 1, "displayed time");
    assert_eq!(hits(""), 4, "empty search filters nothing");
    // A needle spanning two columns must not match: the separator between
    // them is not part of any value.
    assert_eq!(hits("CreateUsersignin"), 0, "no cross-column match");
    // The needle is a literal, not a pattern. Under `LIKE` these would be
    // wildcards and would match `198.51.100.7` and every row.
    assert_eq!(hits("100_7"), 0, "underscore is not a wildcard");
    assert_eq!(hits("%"), 0, "percent is not a wildcard");
}

#[test]
fn the_all_events_view_filters_and_sorts_the_same_way() {
    let (_tmp, store) = timed();

    let page = results::all_events(
        &store,
        &results::Window {
            offset: 0,
            limit: 10,
            search: "203.0.113".into(),
            newest_first: true,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(
        page.rows
            .iter()
            .map(|r| r.event_name.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["ConsoleLogin", "CreateUser"]
    );
    // Paging needs the filtered total, or the list stops short or over-fetches.
    assert_eq!(page.total, 2);
}

#[test]
fn a_page_size_the_ui_could_get_wrong_is_clamped_not_obeyed() {
    let (_tmp, store) = timed();
    let rows = |limit| {
        results::all_events(
            &store,
            &results::Window {
                offset: 0,
                limit,
                ..Default::default()
            },
        )
        .unwrap()
        .rows
        .len()
    };

    // Zero would page forever without ever showing a row, so it floors at one.
    assert_eq!(rows(0), 1, "a zero limit still returns a page");
    // And the ceiling keeps one response from carrying a whole case (NFR-2).
    assert_eq!(
        results::Window {
            limit: u64::MAX,
            ..Default::default()
        }
        .page_limit(),
        1_000
    );
}
