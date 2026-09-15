//! Payload key discovery: every leaf path inside the JSON payload columns,
//! counted per log type, so the rule editor can offer what the data has
//! (docs/04 "페이로드 키").

mod support;

use awslog_core::model::NormalizedEvent;
use awslog_core::payload::KeyCounter;
use serde_json::json;

fn event(request: &str, response: &str, resources: Option<&str>) -> NormalizedEvent {
    NormalizedEvent {
        file_id: 0,
        record_index: 0,
        event_time: None,
        event_source: None,
        event_name: None,
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
        request: Some(request.to_owned()),
        response: Some(response.to_owned()),
        resources: resources.map(str::to_owned),
        raw: None,
    }
}

fn sorted(counter: &KeyCounter) -> Vec<(String, u64)> {
    let mut out: Vec<_> = counter
        .counts()
        .map(|(path, n)| (path.to_owned(), n))
        .collect();
    out.sort();
    out
}

#[test]
fn leaf_paths_are_counted_per_column_with_arrays_indexed() {
    let mut keys = KeyCounter::default();
    let put = event(
        r#"{"bucketName":"b","tagging":{"tagSet":[{"key":"k"},{"key":"k2"}]},"gone":null,"empty":{}}"#,
        r#"{"x-amz-expiration":"expiry","x-amz-server-side-encryption":"AES256"}"#,
        Some(r#"[{"ARN":"arn:aws:s3:::b","type":"AWS::S3::Bucket"}]"#),
    );
    let get = event(r#"{"bucketName":"b"}"#, "{}", None);

    keys.record_event(&put);
    keys.record_event(&get);

    // Paths are spelled the way a rule addresses them; nulls and empty
    // containers name nothing an event has.
    assert_eq!(
        sorted(&keys),
        [
            ("request.bucketName".to_owned(), 2),
            ("request.tagging.tagSet.0.key".to_owned(), 1),
            ("request.tagging.tagSet.1.key".to_owned(), 1),
            ("resources.0.ARN".to_owned(), 1),
            ("resources.0.type".to_owned(), 1),
            ("response.x-amz-expiration".to_owned(), 1),
            ("response.x-amz-server-side-encryption".to_owned(), 1),
        ]
    );
}

#[test]
fn discovery_is_bounded_in_depth_width_and_size() {
    let mut keys = KeyCounter::default();

    // Beyond the fifth element a list is data, not shape.
    let wide: Vec<_> = (0..10).map(|i| json!({ "n": i })).collect();
    keys.record("request", &json!({ "items": wide }));
    assert_eq!(keys.len(), 5, "array indexes stop at 4");

    // Beyond six levels a path is no longer something an analyst types.
    let deep = json!({"a":{"b":{"c":{"d":{"e":{"f":{"g":1}}}}}}});
    let mut only_deep = KeyCounter::default();
    only_deep.record("request", &deep);
    assert_eq!(
        only_deep.len(),
        0,
        "seven segments below the column are dropped"
    );
    let six = json!({"a":{"b":{"c":{"d":{"e":{"f":1}}}}}});
    only_deep.record("request", &six);
    assert_eq!(sorted(&only_deep), [("request.a.b.c.d.e.f".to_owned(), 1)]);

    // A runaway schema (say, keys that are ids) stops adding paths; the
    // ones already known keep counting.
    let mut many = KeyCounter::default();
    for i in 0..6_000 {
        many.record("request", &json!({ format!("k{i}"): 1 }));
    }
    assert_eq!(many.len(), KeyCounter::MAX_PATHS);
    many.record("request", &json!({ "k0": 1 }));
    assert_eq!(
        many.counts()
            .find(|(path, _)| *path == "request.k0")
            .map(|(_, n)| n),
        Some(2)
    );
}

#[test]
fn counters_merge_by_summing() {
    let mut a = KeyCounter::default();
    a.record("request", &json!({ "x": 1, "y": 1 }));
    let mut b = KeyCounter::default();
    b.record("request", &json!({ "x": 1 }));
    b.record("response", &json!({ "z": 1 }));

    a.merge(b);

    assert_eq!(
        sorted(&a),
        [
            ("request.x".to_owned(), 2),
            ("request.y".to_owned(), 1),
            ("response.z".to_owned(), 1),
        ]
    );
}
