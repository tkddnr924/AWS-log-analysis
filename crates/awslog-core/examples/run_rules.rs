//! Dev helper: evaluate the shipped rules (plus an optional user rules
//! directory) against a parsed case.

use std::path::PathBuf;

use awslog_core::rule::{self, RuleSet};
use awslog_core::store::Store;

fn main() {
    let mut args = std::env::args().skip(1);
    let case_db = PathBuf::from(
        args.next()
            .expect("usage: run_rules <session.duckdb> [user_rules_dir]"),
    );
    let user_dir = PathBuf::from(args.next().unwrap_or_default());

    let set = RuleSet::load_layered(&user_dir).expect("rules");
    for error in set.errors() {
        eprintln!("rule error {}: {}", error.path.display(), error.message);
    }
    println!("loaded {} rules", set.rules().len());

    let store = Store::open(&case_db).expect("store");
    let mut sink_store = store.writer_handle().expect("writer");

    // Clears previous hits and records rule metadata in one call.
    sink_store
        .begin_rule_run(set.rules())
        .expect("begin rule run");

    // Both sides stream: events are read one at a time and hits leave in
    // bounded batches, so neither is ever fully in memory (NFR-2).
    // Both sides stream: events arrive one at a time and hits leave in
    // bounded batches, so neither is ever fully in memory (NFR-2).
    let mut sink = |batch: &[(String, rule::Hit)]| sink_store.append_match_batch(batch);
    let mut streamer = rule::MatchStreamer::new(&set, 10_000);
    store
        .for_each_typed_event(|id, log_type, event| {
            streamer.push_for_log_type(id, log_type, &event, &mut sink)
        })
        .expect("scan events");
    let summary = streamer.finish(&mut sink).expect("summary");

    println!("events {} | unmatched {}", summary.total, summary.unmatched);
    for rule in &summary.rules {
        println!(
            "  [{}] {} — {} hits ({})",
            rule.severity, rule.rule_id, rule.match_count, rule.description
        );
    }
    println!(
        "stored matches {}",
        sink_store.match_count().expect("count")
    );
}
