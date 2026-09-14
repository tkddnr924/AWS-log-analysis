//! The store needs nothing but the executable (docs/07): DuckDB must not
//! fetch its JSON extension into the home directory, which needs network
//! access and writes outside `cases/`. Own file so the process is single-test
//! and HOME can be pointed at a scratch directory before DuckDB reads it.

use awslog_core::model::NormalizedEvent;
use awslog_core::results;
use awslog_core::store::Store;

#[test]
fn json_columns_work_without_touching_the_home_directory() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", home.path());
    std::env::set_var("USERPROFILE", home.path());

    let case = tempfile::tempdir().unwrap();
    let mut store = Store::create(&case.path().join("s.duckdb"), "c1", "/logs").unwrap();
    store.register_file(0, "a.log.gz", 1, "alb_access").unwrap();
    store
        .append_events(&[NormalizedEvent {
            file_id: 0,
            record_index: 0,
            event_time: None,
            event_source: None,
            event_name: Some("GET".into()),
            aws_region: None,
            account_id: None,
            source_ip: None,
            user_agent: None,
            identity_type: None,
            identity_arn: None,
            identity_name: None,
            mfa_authenticated: None,
            error_code: None,
            error_message: None,
            read_only: None,
            management_event: None,
            request: Some(r#"{"method":"GET","url":"https://example.test/"}"#.into()),
            response: Some(r#"{"elb_status_code":503}"#.into()),
            resources: None,
            raw: None,
        }])
        .unwrap();

    // The row summary goes through json_extract_string.
    let page = results::all_events(&store, &Default::default()).unwrap();
    assert_eq!(page.rows[0].status.as_deref(), Some("503"));

    assert!(
        !home.path().join(".duckdb").exists(),
        "DuckDB wrote into the home directory"
    );
}
