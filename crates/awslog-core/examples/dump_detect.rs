//! Dev helper: print the GUI payload for a directory as JSON.
//! Used to verify the detection screen without driving the folder picker.

use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("usage: dump_detect <dir>"));
    let scanned = awslog_core::scan::scan_dir(&root).expect("scan");
    let summary = awslog_core::report::summarize_scan(&scanned);
    let rows = awslog_core::report::detect_all(&root, &scanned);

    println!(
        "{}",
        serde_json::json!({ "summary": summary, "rows": rows })
    );
}
