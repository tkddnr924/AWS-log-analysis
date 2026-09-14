//! Core logic for AWS log analysis: scanning, detection, parsing, rules.
//! Contains no GUI dependency so it can be tested without Tauri.

pub mod detect;
pub mod logging;
pub mod mapping;
pub mod model;
pub mod ndjson;
pub mod parse;
pub mod paths;
pub mod report;
pub mod results;
pub mod rule;
pub mod scan;
pub mod store;
