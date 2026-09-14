//! FR-8 run logs land inside the case directory and carry no event bodies.

use awslog_core::logging::{AppLog, CaseLog};
use awslog_core::paths;
use std::path::Path;
use time::macros::datetime;

#[test]
fn app_log_is_written_inside_cases_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();

    let log = AppLog::open(&root).unwrap();
    log.info("startup");
    drop(log);

    let path = root.path().join("app.log");
    assert!(path.is_file(), "expected {}", path.display());
    assert!(std::fs::read_to_string(&path).unwrap().contains("startup"));
}

#[test]
fn parse_and_warning_logs_are_separate_files_in_the_case() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();
    let case = root
        .create_case(Path::new("/logs/prod"), datetime!(2026-09-11 10:00:00))
        .unwrap();

    let log = CaseLog::open(&case).unwrap();
    log.info("parse started");
    log.warn_record_failure(Path::new("/logs/prod/a.json.gz"), 42, "invalid JSON");
    drop(log);

    let parse = std::fs::read_to_string(case.logs_dir().join("parse.log")).unwrap();
    let warnings = std::fs::read_to_string(case.logs_dir().join("warnings.log")).unwrap();

    assert!(parse.contains("parse started"));
    assert!(
        !parse.contains("invalid JSON"),
        "warnings belong in warnings.log"
    );
    assert!(warnings.contains("a.json.gz"));
    assert!(warnings.contains("42"));
    assert!(warnings.contains("invalid JSON"));
}

#[test]
fn warning_redacts_event_body_so_account_data_never_reaches_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();
    let case = root
        .create_case(Path::new("/logs/prod"), datetime!(2026-09-11 10:00:00))
        .unwrap();

    let log = CaseLog::open(&case).unwrap();
    // A parser error string may embed the offending record; it must not be logged verbatim.
    log.warn_record_failure(
        Path::new("/logs/prod/a.json.gz"),
        7,
        r#"invalid type at {"userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"}}"#,
    );
    drop(log);

    let warnings = std::fs::read_to_string(case.logs_dir().join("warnings.log")).unwrap();
    assert!(
        !warnings.contains("123456789012"),
        "account id leaked: {warnings}"
    );
    assert!(!warnings.contains("alice"), "principal leaked: {warnings}");
    assert!(warnings.contains("a.json.gz"));
}
