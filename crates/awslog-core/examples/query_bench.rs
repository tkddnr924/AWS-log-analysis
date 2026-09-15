use std::path::PathBuf;
use std::time::Instant;

use awslog_core::results::{self, Window};
use awslog_core::store::Store;

fn main() {
    let db = PathBuf::from(std::env::args().nth(1).expect("db"));
    let t = Instant::now();
    let store = Store::open(&db).expect("open");
    println!("open {:?}", t.elapsed());
    for (search, newest) in [("", false), ("", true), ("POST", false), ("43.201", true)] {
        let t = Instant::now();
        let page = results::all_events(
            &store,
            &Window {
                offset: 0,
                limit: 1000,
                search: search.to_owned(),
                newest_first: newest,
                ..Default::default()
            },
        )
        .expect("query");
        println!(
            "all_events search={search:?} newest={newest} rows={} total={} {:?}",
            page.rows.len(),
            page.total,
            t.elapsed()
        );
    }
    let t = Instant::now();
    let page = results::query(&store, &Window::default()).expect("groups");
    println!(
        "groups {} total_events={} matched={} {:?}",
        page.groups.len(),
        page.total_events,
        page.matched_events,
        t.elapsed()
    );
    for g in &page.groups {
        let t = Instant::now();
        let page = results::rule_matches(
            &store,
            &g.rule_id,
            &Window {
                offset: 0,
                limit: 1000,
                ..Default::default()
            },
        )
        .expect("rule page");
        println!(
            "rule {} count={} rows={} {:?}",
            g.rule_id,
            g.match_count,
            page.rows.len(),
            t.elapsed()
        );
    }
}
