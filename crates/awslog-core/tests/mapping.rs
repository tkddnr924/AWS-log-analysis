//! Field mapping: which JSON path feeds each stored column (docs/03).

use awslog_core::mapping::{resolve, Field, FieldMap};
use serde_json::json;

#[test]
fn resolves_nested_and_indexed_paths() {
    let record = json!({
        "userIdentity": { "sessionContext": { "attributes": { "mfaAuthenticated": "true" } } },
        "resources": [{ "type": "AWS::S3::Object" }, { "type": "AWS::S3::Bucket" }],
    });

    assert_eq!(
        resolve(
            &record,
            "userIdentity.sessionContext.attributes.mfaAuthenticated"
        ),
        Some(&json!("true"))
    );
    assert_eq!(
        resolve(&record, "resources.1.type"),
        Some(&json!("AWS::S3::Bucket"))
    );
}

#[test]
fn a_missing_or_mistyped_path_yields_nothing_instead_of_failing() {
    let record = json!({ "eventName": "ConsoleLogin" });

    assert_eq!(resolve(&record, "userIdentity.arn"), None);
    // Descending into a scalar must not panic or match.
    assert_eq!(resolve(&record, "eventName.nope"), None);
    assert_eq!(resolve(&record, "resources.0"), None);
}

#[test]
fn later_sources_are_tried_when_the_first_is_absent() {
    let map = FieldMap::cloudtrail();
    let console_login = json!({ "additionalEventData": { "MFAUsed": "Yes" } });
    let assumed_role = json!({
        "userIdentity": { "sessionContext": { "attributes": { "mfaAuthenticated": "true" } } }
    });

    assert_eq!(
        map.lookup(&console_login, Field::MfaAuthenticated),
        Some(&json!("Yes"))
    );
    assert_eq!(
        map.lookup(&assumed_role, Field::MfaAuthenticated),
        Some(&json!("true"))
    );
}

#[test]
fn an_override_replaces_the_default_path_for_that_field_only() {
    let mut map = FieldMap::cloudtrail();
    map.set(Field::SourceIp, vec!["requestContext.clientIp".to_owned()]);
    let record = json!({
        "sourceIPAddress": "203.0.113.10",
        "requestContext": { "clientIp": "198.51.100.7" },
        "eventName": "ConsoleLogin",
    });

    assert_eq!(
        map.lookup(&record, Field::SourceIp),
        Some(&json!("198.51.100.7"))
    );
    // Untouched fields keep working.
    assert_eq!(
        map.lookup(&record, Field::EventName),
        Some(&json!("ConsoleLogin"))
    );
}

#[test]
fn a_partial_mapping_falls_back_to_defaults_for_unnamed_fields() {
    // What the UI sends when the user edited one row of the editor.
    let map: FieldMap = serde_json::from_str(r#"{"event_name": ["operation"]}"#).unwrap();
    let record = json!({ "operation": "PutObject", "awsRegion": "ap-northeast-2" });

    assert_eq!(
        map.lookup(&record, Field::EventName),
        Some(&json!("PutObject"))
    );
    assert_eq!(
        map.lookup(&record, Field::AwsRegion),
        Some(&json!("ap-northeast-2"))
    );
}

#[test]
fn json_null_counts_as_absent() {
    let map = FieldMap::cloudtrail();
    let record = json!({ "errorCode": null });

    assert_eq!(map.lookup(&record, Field::ErrorCode), None);
}

#[test]
fn field_keys_round_trip() {
    for field in Field::ALL {
        assert_eq!(Field::from_key(field.key()), Some(field));
    }
}

#[test]
fn coercion_failure_falls_through_to_the_next_source() {
    let map = FieldMap::cloudtrail();
    // First path present but not a usable boolean; the second one is.
    let record = json!({
        "userIdentity": { "sessionContext": { "attributes": { "mfaAuthenticated": "maybe" } } },
        "additionalEventData": { "MFAUsed": "Yes" },
    });

    assert_eq!(
        map.lookup_with(
            &record,
            Field::MfaAuthenticated,
            awslog_core::mapping::as_bool
        ),
        Some(true)
    );
}

#[test]
fn booleans_accept_every_spelling_cloudtrail_uses() {
    use awslog_core::mapping::as_bool;

    assert_eq!(as_bool(&json!(true)), Some(true));
    assert_eq!(as_bool(&json!("true")), Some(true));
    assert_eq!(as_bool(&json!("Yes")), Some(true));
    assert_eq!(as_bool(&json!("No")), Some(false));
    assert_eq!(as_bool(&json!("mayonnaise")), None);
    assert_eq!(as_bool(&json!(1)), None);
}
