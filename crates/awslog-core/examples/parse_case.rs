//! Dev helper: run a full parse into a real case directory and print the
//! artifacts it produced. Verifies the FR-5/FR-7/FR-8 wiring end to end.

use std::path::PathBuf;

use awslog_core::logging::CaseLog;
use awslog_core::parse::{self, ParseOptions};
use awslog_core::paths;
use awslog_core::store::{CaseStatus, Store};
use time::{OffsetDateTime, PrimitiveDateTime};

fn main() {
    let mut args = std::env::args().skip(1);
    let input = PathBuf::from(
        args.next()
            .expect("usage: parse_case <input> <cases_root> [--without-raw]"),
    );
    let cases_root = PathBuf::from(
        args.next()
            .expect("usage: parse_case <input> <cases_root> [--without-raw]"),
    );
    let keep_raw = args.next().as_deref() != Some("--without-raw");
    let root = paths::prepare(&cases_root).expect("cases root");
    let now = OffsetDateTime::now_utc();
    let case = root
        .create_case(&input, PrimitiveDateTime::new(now.date(), now.time()))
        .expect("case dir");

    let log = CaseLog::open(&case).expect("case log");
    log.info("parse started");

    let mut store =
        Store::create(&case.session_db(), case.id(), &input.display().to_string()).expect("store");
    store.set_temp_dir(case.dir()).expect("temp dir");

    let options = ParseOptions {
        keep_raw,
        ..ParseOptions::default()
    };
    let outcome = parse::run(&input, &mut store, &options, &|p| {
        if p.files_done == p.files_total {
            println!(
                "progress {}/{} records={}",
                p.files_done, p.files_total, p.records_parsed
            );
        }
    })
    .expect("parse");

    for failure in &outcome.failures {
        log.warn_file_skipped(std::path::Path::new(&failure.display_path), &failure.reason);
    }

    // Like the app: rules are registered pending and evaluated on demand.
    let rules = awslog_core::rule::RuleSet::load_layered(&root.user_rules_dir()).expect("rules");
    store
        .writer_handle()
        .expect("writer")
        .begin_rule_run(rules.rules())
        .expect("register rules");

    store.finish(CaseStatus::Done).expect("finish");
    store.write_case_json(case.dir()).expect("case.json");
    log.info(&format!(
        "parse finished records={}",
        outcome.records_parsed
    ));

    println!("case_id     {}", case.id());
    println!("outcome     {outcome:?}");
    println!(
        "events      {}",
        store.event_count(&Default::default()).expect("count")
    );
}
