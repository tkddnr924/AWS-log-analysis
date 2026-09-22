//! Incident-analysis pack behavior: the shipped CloudTrail rules that flag
//! identity, monitoring and remote-access changes. Every assertion runs the
//! rule text compiled into the binary (`RuleSet::shipped`), never a copy, so a
//! rule edit that changes what an analyst sees fails here.
//!
//! Fixtures are masked (`203.0.113.x`, `000000000000`, `masked`).

mod support;

use std::sync::LazyLock;

use awslog_core::model::NormalizedEvent;
use awslog_core::parse::{self, ParseOptions};
use awslog_core::rule::{evaluate, RuleSet};
use awslog_core::store::Store;
use support::{cloudtrail_json, gzip, write};
use time::macros::datetime;

const ADMIN: &str = "arn:aws:iam::aws:policy/AdministratorAccess";

/// The rule pack compiled into the binary; a pack that fails to load would
/// make every assertion below meaningless.
static SHIPPED: LazyLock<RuleSet> = LazyLock::new(|| {
    let set = RuleSet::shipped();
    assert!(set.errors().is_empty(), "{:?}", set.errors());
    set
});

/// Whether the shipped rule `id` fires on `event`. Also pins that the rule is
/// reachable for CloudTrail events at all: a missing `meta: log_type` or a typo
/// there silently disables the detection with no error.
fn hits(id: &str, event: &NormalizedEvent) -> bool {
    let rule = SHIPPED
        .rule(id)
        .unwrap_or_else(|| panic!("shipped pack has no rule {id}"));
    assert!(
        rule.applies_to("cloudtrail"),
        "{id} does not run on cloudtrail"
    );
    evaluate(rule, event).is_some()
}

/// A masked management event with no recorded error or response.
fn event(source: &str, name: &str) -> NormalizedEvent {
    NormalizedEvent {
        file_id: 0,
        record_index: 0,
        event_time: Some(datetime!(2026-09-11 02:03:04).assume_utc()),
        event_source: Some(source.into()),
        event_name: Some(name.into()),
        aws_region: Some("ap-northeast-2".into()),
        account_id: Some("000000000000".into()),
        source_ip: Some("203.0.113.10".into()),
        user_agent: Some("aws-cli/2.15.0".into()),
        identity_type: Some("IAMUser".into()),
        identity_arn: Some("arn:aws:iam::000000000000:user/masked".into()),
        identity_name: Some("masked".into()),
        mfa_authenticated: Some(true),
        error_code: None,
        error_message: None,
        read_only: Some(false),
        management_event: Some(true),
        request: None,
        response: None,
        resources: None,
        raw: None,
    }
}

fn req(source: &str, name: &str, request: &str) -> NormalizedEvent {
    NormalizedEvent {
        request: Some(request.into()),
        ..event(source, name)
    }
}

/// The same call rejected by authorization. An attempt is still an attempt, so
/// every rule in this pack must keep firing.
fn denied(mut event: NormalizedEvent) -> NormalizedEvent {
    event.error_code = Some("AccessDenied".into());
    event.error_message =
        Some("User: arn:aws:iam::000000000000:user/masked is not authorized".into());
    event
}

fn attach(name: &str, policy_arn: &str) -> NormalizedEvent {
    req(
        "iam.amazonaws.com",
        name,
        &format!(r#"{{"userName":"masked","policyArn":"{policy_arn}"}}"#),
    )
}

// ---------------------------------------------------------------- scoping

#[test]
fn the_incident_rules_only_run_on_cloudtrail_events() {
    let set = &*SHIPPED;
    for id in [
        "cloudtrail_role_trust_change_attempt",
        "cloudtrail_admin_policy_attach_attempt",
        "cloudtrail_console_profile_change_attempt",
        "cloudtrail_mfa_deactivation_attempt",
        "cloudtrail_ssm_remote_access_attempt",
        "cloudtrail_root_console_login_success",
        "cloudtrail_login_without_mfa_success",
    ] {
        let rule = set
            .rule(id)
            .unwrap_or_else(|| panic!("shipped pack has no rule {id}"));
        assert!(
            rule.applies_to("cloudtrail"),
            "{id} does not run on cloudtrail"
        );
        // Column names mean different things per log type; an unscoped rule
        // would be evaluated against ALB and WAF events too.
        for other in ["alb_access", "waf_acl", "apigw_access", "nginx_access"] {
            assert!(!rule.applies_to(other), "{id} also runs on {other}");
        }
    }
}

// ------------------------------------------------------- role trust policy

#[test]
fn role_trust_policy_updates_are_flagged_including_denied_attempts() {
    let id = "cloudtrail_role_trust_change_attempt";
    let update = req(
        "iam.amazonaws.com",
        "UpdateAssumeRolePolicy",
        r#"{"roleName":"masked-role","policyDocument":"{}"}"#,
    );

    assert!(hits(id, &update));
    assert!(hits(id, &denied(update.clone())));

    // One field apart: a neighbouring IAM call, and the same call name from
    // another service.
    assert!(!hits(id, &event("iam.amazonaws.com", "UpdateRole")));
    assert!(!hits(id, &event("iam.amazonaws.com", "GetRole")));
    assert!(!hits(
        id,
        &NormalizedEvent {
            event_source: Some("sts.amazonaws.com".into()),
            ..update
        }
    ));
}

// ------------------------------------------------------ admin policy attach

#[test]
fn only_the_exact_administrator_access_policy_counts_as_an_admin_attachment() {
    let id = "cloudtrail_admin_policy_attach_attempt";

    // A customer-managed policy may be named AdministratorAccess without
    // granting it: the account id is in the ARN, not `aws`.
    assert!(!hits(
        id,
        &attach(
            "AttachUserPolicy",
            "arn:aws:iam::000000000000:policy/AdministratorAccess"
        )
    ));
    // Real managed policies whose names start with the same text.
    assert!(!hits(
        id,
        &attach(
            "AttachRolePolicy",
            "arn:aws:iam::aws:policy/AdministratorAccess-Amplify"
        )
    ));
    assert!(!hits(
        id,
        &attach("AttachUserPolicy", "arn:aws:iam::aws:policy/ReadOnlyAccess")
    ));

    // An attach with no policy ARN in the payload, and with a null leaf.
    assert!(!hits(
        id,
        &req(
            "iam.amazonaws.com",
            "AttachUserPolicy",
            r#"{"userName":"masked"}"#
        )
    ));
    assert!(!hits(
        id,
        &req(
            "iam.amazonaws.com",
            "AttachUserPolicy",
            r#"{"userName":"masked","policyArn":null}"#
        )
    ));
    assert!(!hits(id, &event("iam.amazonaws.com", "AttachUserPolicy")));

    // Inline policy writes and policy-version changes are a different rule,
    // even when the document grants administrator access.
    assert!(!hits(
        id,
        &req(
            "iam.amazonaws.com",
            "PutUserPolicy",
            &format!(r#"{{"userName":"masked","policyArn":"{ADMIN}"}}"#)
        )
    ));
    // The same payload from another service is not an IAM attachment.
    assert!(!hits(
        id,
        &req(
            "sts.amazonaws.com",
            "AttachUserPolicy",
            &format!(r#"{{"policyArn":"{ADMIN}"}}"#)
        )
    ));
}

// ---------------------------------------------------------- login profile

#[test]
fn console_password_creation_and_reset_are_flagged() {
    let id = "cloudtrail_console_profile_change_attempt";
    let create = req(
        "iam.amazonaws.com",
        "CreateLoginProfile",
        r#"{"userName":"masked","passwordResetRequired":false}"#,
    );

    assert!(hits(id, &create));
    assert!(hits(id, &event("iam.amazonaws.com", "UpdateLoginProfile")));
    assert!(hits(id, &denied(create.clone())));

    assert!(!hits(id, &event("iam.amazonaws.com", "GetLoginProfile")));
    assert!(!hits(id, &event("iam.amazonaws.com", "DeleteLoginProfile")));
    assert!(!hits(
        id,
        &NormalizedEvent {
            event_source: Some("signin.amazonaws.com".into()),
            ..create
        }
    ));
}

// ------------------------------------------------------------------- MFA

#[test]
fn mfa_deactivation_is_flagged_but_enrolment_is_not() {
    let id = "cloudtrail_mfa_deactivation_attempt";
    let off = req(
        "iam.amazonaws.com",
        "DeactivateMFADevice",
        r#"{"userName":"masked","serialNumber":"arn:aws:iam::000000000000:mfa/masked"}"#,
    );

    assert!(hits(id, &off));
    assert!(hits(id, &denied(off.clone())));

    assert!(!hits(id, &event("iam.amazonaws.com", "EnableMFADevice")));
    assert!(!hits(
        id,
        &event("iam.amazonaws.com", "DeleteVirtualMFADevice")
    ));
    assert!(!hits(
        id,
        &NormalizedEvent {
            event_source: Some("sts.amazonaws.com".into()),
            ..off
        }
    ));
}

// ------------------------------------------------------------ SSM access

#[test]
fn ssm_remote_command_and_session_access_is_flagged() {
    let id = "cloudtrail_ssm_remote_access_attempt";
    let send = req(
        "ssm.amazonaws.com",
        "SendCommand",
        r#"{"instanceIds":["i-0000000000000dead"],"documentName":"AWS-RunShellScript"}"#,
    );
    let session = req(
        "ssm.amazonaws.com",
        "StartSession",
        r#"{"target":"i-0000000000000dead"}"#,
    );

    assert!(hits(id, &send));
    assert!(hits(id, &session));
    assert!(hits(id, &denied(send.clone())));
    assert!(hits(id, &denied(session)));

    // Read-only SSM traffic and session teardown are not remote access.
    assert!(!hits(
        id,
        &event("ssm.amazonaws.com", "DescribeInstanceInformation")
    ));
    assert!(!hits(id, &event("ssm.amazonaws.com", "TerminateSession")));
    assert!(!hits(id, &event("ssm.amazonaws.com", "ListCommands")));
    // Same call name, wrong service.
    assert!(!hits(
        id,
        &NormalizedEvent {
            event_source: Some("ec2.amazonaws.com".into()),
            ..send
        }
    ));
}

// ---------------------------------------------------- monitoring disabled

#[test]
fn guardduty_detector_updates_are_flagged_only_when_they_switch_it_off() {
    let id = "cloudtrail_monitoring_disabled";
    let update = |payload: &str| req("guardduty.amazonaws.com", "UpdateDetector", payload);

    assert!(hits(
        id,
        &update(r#"{"detectorId":"masked","enable":false}"#)
    ));
    // CloudTrail writes some request booleans as strings; the payload is stored
    // verbatim, so the rule must still see it as off.
    assert!(hits(
        id,
        &update(r#"{"detectorId":"masked","enable":"false"}"#)
    ));
    assert!(hits(
        id,
        &denied(update(r#"{"detectorId":"masked","enable":false}"#))
    ));

    // Turning monitoring back on, or any other detector setting, is not a
    // disablement — and "enable" absent or null says nothing at all.
    assert!(!hits(
        id,
        &update(r#"{"detectorId":"masked","enable":true}"#)
    ));
    assert!(!hits(
        id,
        &update(r#"{"detectorId":"masked","enable":"true"}"#)
    ));
    assert!(!hits(
        id,
        &update(r#"{"detectorId":"masked","findingPublishingFrequency":"SIX_HOURS"}"#)
    ));
    assert!(!hits(
        id,
        &update(r#"{"detectorId":"masked","enable":null}"#)
    ));
    assert!(!hits(
        id,
        &event("guardduty.amazonaws.com", "UpdateDetector")
    ));
}

#[test]
fn detector_deletion_and_security_hub_disablement_stay_flagged_per_service() {
    let id = "cloudtrail_monitoring_disabled";

    assert!(hits(
        id,
        &req(
            "guardduty.amazonaws.com",
            "DeleteDetector",
            r#"{"detectorId":"masked"}"#
        )
    ));
    // The `enable` gate belongs to UpdateDetector alone; a deletion carries no
    // such flag and must not be filtered out by it.
    assert!(hits(
        id,
        &req(
            "guardduty.amazonaws.com",
            "DeleteDetector",
            r#"{"detectorId":"masked","enable":true}"#
        )
    ));
    assert!(hits(
        id,
        &event("securityhub.amazonaws.com", "DisableSecurityHub")
    ));
    assert!(hits(
        id,
        &denied(event("securityhub.amazonaws.com", "DisableSecurityHub"))
    ));

    // Each call name belongs to one service; the cross pairs are impossible
    // events and must not match.
    assert!(!hits(
        id,
        &event("securityhub.amazonaws.com", "DeleteDetector")
    ));
    assert!(!hits(
        id,
        &req(
            "securityhub.amazonaws.com",
            "UpdateDetector",
            r#"{"detectorId":"masked","enable":false}"#
        )
    ));
    assert!(!hits(
        id,
        &event("guardduty.amazonaws.com", "DisableSecurityHub")
    ));
    assert!(!hits(
        id,
        &req(
            "config.amazonaws.com",
            "UpdateDetector",
            r#"{"detectorId":"masked","enable":false}"#
        )
    ));
    // Enabling Security Hub is the opposite action.
    assert!(!hits(
        id,
        &event("securityhub.amazonaws.com", "EnableSecurityHub")
    ));
}

// ------------------------------------------------------- root credentials

/// Root identity for testing activity outside ConsoleLogin.
fn root(source: &str, name: &str) -> NormalizedEvent {
    NormalizedEvent {
        identity_type: Some("Root".into()),
        identity_arn: Some("arn:aws:iam::000000000000:root".into()),
        identity_name: None,
        ..event(source, name)
    }
}

#[test]
fn root_api_use_needs_a_recorded_event_name() {
    let id = "cloudtrail_root_api_activity";

    assert!(hits(id, &root("iam.amazonaws.com", "CreateUser")));
    assert!(hits(
        id,
        &denied(root("s3.amazonaws.com", "PutBucketPolicy"))
    ));

    // The sign-in itself is what the console-login rules report.
    assert!(!hits(id, &root("signin.amazonaws.com", "ConsoleLogin")));
    // One field apart: the same call by an IAM user.
    assert!(!hits(id, &event("iam.amazonaws.com", "CreateUser")));

    // `not $login` is also true when there is no event name at all, so a
    // record that lost `eventName` — a mapping override, a truncated export —
    // would be reported as root API use with no call to show for it.
    assert!(!hits(
        id,
        &NormalizedEvent {
            event_name: None,
            ..root("iam.amazonaws.com", "CreateUser")
        }
    ));
}

// ------------------------------------------------------ AssumeRole duration

#[test]
fn long_sessions_are_sts_assume_role_requests_over_the_threshold() {
    let id = "cloudtrail_long_lived_session";
    let assume = |source: &str, duration: &str| {
        req(
            source,
            "AssumeRole",
            &format!(
                r#"{{"roleArn":"arn:aws:iam::000000000000:role/masked-role","roleSessionName":"masked","durationSeconds":{duration}}}"#
            ),
        )
    };

    assert!(hits(id, &assume("sts.amazonaws.com", "43200")));
    // Some exports write the number as a string; it still compares numerically.
    assert!(hits(id, &assume("sts.amazonaws.com", r#""43200""#)));
    assert!(hits(id, &denied(assume("sts.amazonaws.com", "14401"))));

    // The threshold itself is not over it, and a shorter request is ordinary.
    assert!(!hits(id, &assume("sts.amazonaws.com", "14400")));
    assert!(!hits(id, &assume("sts.amazonaws.com", "3600")));
    // Missing duration does not establish a request above the threshold.
    assert!(!hits(id, &assume("sts.amazonaws.com", "null")));
    assert!(!hits(id, &event("sts.amazonaws.com", "AssumeRole")));

    // `AssumeRole` is an STS call; the same name and payload attributed to
    // another service is not a session request.
    assert!(!hits(id, &assume("iam.amazonaws.com", "43200")));
    assert!(!hits(id, &assume("ec2.amazonaws.com", "43200")));
    // The federated variants carry their own duration and stay out of scope.
    assert!(!hits(
        id,
        &req(
            "sts.amazonaws.com",
            "AssumeRoleWithWebIdentity",
            r#"{"durationSeconds":43200}"#
        )
    ));
}

// ------------------------------------------------- through the real pipeline

/// One masked CloudTrail record as the service writes it, with the payload the
/// rules read from `requestParameters`.
fn cloudtrail_call(source: &str, name: &str, request: &str) -> String {
    format!(
        r#"{{"eventVersion":"1.08","eventTime":"2026-09-11T02:03:04Z","eventSource":"{source}","eventName":"{name}","awsRegion":"ap-northeast-2","sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.15.0","recipientAccountId":"000000000000","userIdentity":{{"type":"IAMUser","arn":"arn:aws:iam::000000000000:user/masked","userName":"masked"}},"requestParameters":{request},"responseElements":null,"readOnly":false,"managementEvent":true}}"#
    )
}

/// Parses records through the real FR-5 pipeline and returns the stored events,
/// so the payload paths the rules use are the ones normalization produced.
fn parsed(records: &[String]) -> Vec<NormalizedEvent> {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir.path().join("ct.json.gz"),
        &gzip(cloudtrail_json(records).as_bytes()),
    );
    let mut store = Store::create(&dir.path().join("session.duckdb"), "c1", "/logs").unwrap();
    let outcome = parse::run(dir.path(), &mut store, &ParseOptions::default(), &|_| {}).unwrap();
    assert_eq!(outcome.records_parsed, records.len() as u64, "{outcome:?}");

    let mut events = Vec::new();
    store.for_each_event(|_, event| events.push(event)).unwrap();
    events
}

/// The parsed event whose stored `request` payload holds `needle`, so a test
/// never depends on store ordering.
fn with_payload<'a>(events: &'a [NormalizedEvent], needle: &str) -> &'a NormalizedEvent {
    events
        .iter()
        .find(|event| event.request.as_deref().is_some_and(|r| r.contains(needle)))
        .unwrap_or_else(|| panic!("no parsed event carries {needle} in its request"))
}

#[test]
fn an_admin_attachment_parsed_from_a_real_record_reaches_the_admin_rule() {
    let events = parsed(&[
        cloudtrail_call(
            "iam.amazonaws.com",
            "AttachRolePolicy",
            &format!(r#"{{"roleName":"masked-role","policyArn":"{ADMIN}"}}"#),
        ),
        cloudtrail_call(
            "iam.amazonaws.com",
            "AttachRolePolicy",
            r#"{"roleName":"masked-role","policyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}"#,
        ),
    ]);

    let (admin, read_only) = (
        with_payload(&events, "policy/AdministratorAccess"),
        with_payload(&events, "policy/ReadOnlyAccess"),
    );
    assert!(hits("cloudtrail_admin_policy_attach_attempt", admin));
    assert!(!hits("cloudtrail_iam_policy_change", admin));

    assert!(!hits("cloudtrail_admin_policy_attach_attempt", read_only));
    assert!(hits("cloudtrail_iam_policy_change", read_only));
}

#[test]
fn a_detector_update_parsed_from_a_real_record_keeps_its_enable_flag() {
    let events = parsed(&[
        cloudtrail_call(
            "guardduty.amazonaws.com",
            "UpdateDetector",
            r#"{"detectorId":"00000000000000000000000000000000","enable":false}"#,
        ),
        cloudtrail_call(
            "guardduty.amazonaws.com",
            "UpdateDetector",
            r#"{"detectorId":"00000000000000000000000000000000","enable":true}"#,
        ),
    ]);

    assert!(hits(
        "cloudtrail_monitoring_disabled",
        with_payload(&events, r#""enable":false"#)
    ));
    assert!(!hits(
        "cloudtrail_monitoring_disabled",
        with_payload(&events, r#""enable":true"#)
    ));
}

#[test]
fn secret_value_reads_include_batch_and_denied_attempts_not_metadata_reads() {
    let id = "cloudtrail_secret_read_attempt";
    for name in ["GetSecretValue", "BatchGetSecretValue"] {
        let mut read = event("secretsmanager.amazonaws.com", name);
        read.read_only = Some(true);
        assert!(hits(id, &read));
        assert!(hits(id, &denied(read)));
        assert!(!hits(id, &event("ssm.amazonaws.com", name)));
    }
    assert!(!hits(
        id,
        &event("secretsmanager.amazonaws.com", "DescribeSecret")
    ));
    assert!(!hits(
        id,
        &event("secretsmanager.amazonaws.com", "ListSecrets")
    ));
}

#[test]
fn parameter_reads_require_an_explicit_decryption_request() {
    let id = "cloudtrail_parameter_decryption_read_attempt";
    for name in ["GetParameter", "GetParameters", "GetParametersByPath"] {
        let read = req("ssm.amazonaws.com", name, r#"{"withDecryption":true}"#);
        assert!(hits(id, &read));
        assert!(hits(id, &denied(read)));
        for payload in [
            r#"{"withDecryption":false}"#,
            r#"{"withDecryption":null}"#,
            "{}",
        ] {
            assert!(!hits(id, &req("ssm.amazonaws.com", name, payload)));
        }
        assert!(!hits(id, &event("ssm.amazonaws.com", name)));
    }
    assert!(!hits(
        id,
        &req(
            "ssm.amazonaws.com",
            "PutParameter",
            r#"{"withDecryption":true}"#
        )
    ));
    assert!(!hits(
        id,
        &req(
            "ec2.amazonaws.com",
            "GetParameter",
            r#"{"withDecryption":true}"#
        )
    ));
}

#[test]
fn bucket_access_block_removal_uses_the_cloudtrail_not_api_name() {
    let id = "cloudtrail_s3_public_access_block_removal_attempt";
    let removal = req(
        "s3.amazonaws.com",
        "DeleteBucketPublicAccessBlock",
        r#"{"bucketName":"masked-bucket"}"#,
    );
    assert!(hits(id, &removal));
    assert!(hits(id, &denied(removal)));
    for name in [
        "GetBucketPublicAccessBlock",
        "PutBucketPublicAccessBlock",
        "DeletePublicAccessBlock",
        "DeleteAccountPublicAccessBlock",
    ] {
        assert!(!hits(id, &event("s3.amazonaws.com", name)));
    }
    assert!(!hits(
        id,
        &event("s3express.amazonaws.com", "DeleteBucketPublicAccessBlock")
    ));
}

#[test]
fn snapshot_permission_changes_do_not_claim_a_grant_or_completed_sharing() {
    let id = "cloudtrail_snapshot_permission_change_attempt";
    for operation in ["add", "remove"] {
        let change = req(
            "ec2.amazonaws.com",
            "ModifySnapshotAttribute",
            &format!(
                r#"{{"snapshotId":"snap-00000000000000000","attribute":"createVolumePermission","operationType":"{operation}"}}"#
            ),
        );
        assert!(hits(id, &change));
        assert!(hits(id, &denied(change)));
    }
    let mut dry_run = event("ec2.amazonaws.com", "ModifySnapshotAttribute");
    dry_run.error_code = Some("DryRunOperation".into());
    assert!(hits(id, &dry_run));
    assert!(!hits(
        id,
        &event("ec2.amazonaws.com", "DescribeSnapshotAttribute")
    ));
    assert!(!hits(
        id,
        &event("ec2.amazonaws.com", "ModifyImageAttribute")
    ));
    assert!(!hits(
        id,
        &event("rds.amazonaws.com", "ModifySnapshotAttribute")
    ));
}

#[test]
fn decryption_flag_survives_cloudtrail_normalization_and_controls_matching() {
    let events = parsed(&[
        cloudtrail_call(
            "ssm.amazonaws.com",
            "GetParametersByPath",
            r#"{"path":"/masked/","withDecryption":true}"#,
        ),
        cloudtrail_call(
            "ssm.amazonaws.com",
            "GetParametersByPath",
            r#"{"path":"/masked/","withDecryption":false}"#,
        ),
    ]);
    let id = "cloudtrail_parameter_decryption_read_attempt";
    assert!(hits(id, with_payload(&events, r#""withDecryption":true"#)));
    assert!(!hits(
        id,
        with_payload(&events, r#""withDecryption":false"#)
    ));
}

#[test]
fn p2_rules_do_not_interpret_http_events_as_cloudtrail_activity() {
    for id in [
        "cloudtrail_secret_read_attempt",
        "cloudtrail_parameter_decryption_read_attempt",
        "cloudtrail_s3_public_access_block_removal_attempt",
        "cloudtrail_snapshot_permission_change_attempt",
    ] {
        let rule = SHIPPED.rule(id).unwrap();
        assert!(rule.applies_to("cloudtrail"));
        assert!(!rule.applies_to("alb_access"));
        assert!(!rule.applies_to("waf_acl"));
    }
}
