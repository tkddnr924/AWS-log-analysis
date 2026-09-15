//! Pre-parse format preview (FR-4): the head of one file broken into pieces
//! with the meaning each piece feeds, plus what the head holds
//! (docs/03 "포맷 카드").

mod support;

use awslog_core::detect::LogType;
use awslog_core::mapping::{Field, FieldMap};
use awslog_core::preview::{preview_head, HeadPreview};
use support::{cloudtrail_json, cloudtrail_record, gzip, write};

fn cloudtrail_file(records: &[String]) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("trail.json.gz");
    write(&path, &gzip(cloudtrail_json(records).as_bytes()));
    (tmp, path)
}

fn piece<'a>(preview: &'a HeadPreview, path: &str) -> &'a awslog_core::preview::Piece {
    preview
        .pieces
        .iter()
        .find(|p| p.path == path)
        .unwrap_or_else(|| panic!("no piece {path}"))
}

#[test]
fn a_cloudtrail_head_is_summarized_and_its_first_record_labelled() {
    let mut put = cloudtrail_record("PutObject");
    put = put.replace(
        r#""responseElements": {"ConsoleLogin": "Failure"},"#,
        r#""requestParameters": {"bucketName": "img", "tagging": {"tagSet": [{"key": "k"}]}},
            "responseElements": {"x-amz-server-side-encryption": "AES256"},"#,
    );
    // One record without an event name: counted, not "parsed".
    let nameless = cloudtrail_record("GetObject").replace(r#""eventName": "GetObject","#, "");
    let (_tmp, path) = cloudtrail_file(&[
        put,
        cloudtrail_record("PutObject"),
        cloudtrail_record("GetObject"),
        nameless,
    ]);

    let preview = preview_head(&path, LogType::CloudTrail, &FieldMap::cloudtrail()).unwrap();

    assert_eq!(preview.records, 4);
    assert_eq!(preview.mapped, 3);
    assert!(preview.editable, "CloudTrail paths can be re-labelled");
    let names: Vec<_> = preview
        .event_names
        .iter()
        .map(|n| (n.name.as_str(), n.count))
        .collect();
    assert_eq!(names, [("PutObject", 2), ("GetObject", 1)]);

    // Built-in columns are named after the field they feed; payload keys
    // after the rule path; the rest feed nothing.
    let name = piece(&preview, "eventName");
    assert_eq!(name.value, "PutObject");
    assert_eq!(name.field.as_deref(), Some("event_name"));
    assert_eq!(name.label.as_deref(), Some(Field::EventName.label()));
    let bucket = piece(&preview, "requestParameters.bucketName");
    assert_eq!(bucket.field.as_deref(), Some("request.bucketName"));
    assert_eq!(bucket.label.as_deref(), Some("request.bucketName"));
    assert_eq!(
        piece(&preview, "requestParameters.tagging.tagSet.0.key")
            .field
            .as_deref(),
        Some("request.tagging.tagSet.0.key")
    );
    assert_eq!(
        piece(&preview, "responseElements.x-amz-server-side-encryption")
            .field
            .as_deref(),
        Some("response.x-amz-server-side-encryption")
    );
    assert_eq!(piece(&preview, "eventVersion").field, None);
    // Paths across the head, with how many records had them; the ones the
    // first record lacks are what the UI folds under "그 외".
    let console = preview
        .paths
        .iter()
        .find(|p| p.name == "responseElements.ConsoleLogin")
        .unwrap();
    assert_eq!(console.count, 3);
    assert!(preview
        .pieces
        .iter()
        .all(|p| p.path != "responseElements.ConsoleLogin"));
}

#[test]
fn a_relabelled_path_moves_the_label_and_the_parsed_count_follows() {
    let (_tmp, path) = cloudtrail_file(&[cloudtrail_record("PutObject")]);
    let mut map = FieldMap::cloudtrail();
    // The analyst says "the event name is what `eventSource` holds".
    map.set(Field::EventName, vec!["eventSource".to_owned()]);

    let preview = preview_head(&path, LogType::CloudTrail, &map).unwrap();

    assert_eq!(
        piece(&preview, "eventSource").field.as_deref(),
        Some("event_name"),
        "the analyst's assignment wins over the default that also reads this path"
    );
    assert_eq!(piece(&preview, "eventName").field, None);
    assert_eq!(
        preview.event_names[0].name, "signin.amazonaws.com",
        "the histogram follows the mapping"
    );

    map.set(Field::EventName, Vec::new());
    let unmapped = preview_head(&path, LogType::CloudTrail, &map).unwrap();
    assert_eq!(unmapped.mapped, 0, "no event name means not parsed");
}

#[test]
fn ndjson_and_alb_heads_carry_fixed_labels() {
    let tmp = tempfile::tempdir().unwrap();
    let waf = tmp.path().join("waf.log.gz");
    write(
        &waf,
        &gzip(
            format!(
                "{}\n{}\n{}\nnot json\n",
                support::waf_record("BLOCK", "r1"),
                support::waf_record("BLOCK", "r2"),
                support::waf_record("ALLOW", "Default")
            )
            .as_bytes(),
        ),
    );
    let preview = preview_head(&waf, LogType::WafAcl, &FieldMap::cloudtrail()).unwrap();
    assert_eq!(
        (preview.records, preview.mapped),
        (3, 3),
        "the bad line is not a record"
    );
    assert!(!preview.editable);
    assert_eq!(preview.event_names[0].name, "BLOCK");
    assert_eq!(
        piece(&preview, "httpRequest.clientIp").field.as_deref(),
        Some("source_ip")
    );
    assert_eq!(
        piece(&preview, "httpRequest.country").field.as_deref(),
        Some("request.country")
    );

    let alb = tmp.path().join("alb.log.gz");
    write(
        &alb,
        &gzip(
            concat!(
                "h2 2026-08-18T23:50:00.405248Z app/masked-alb/0123456789abcdef 203.0.113.5:44 10.0.0.10:8080 0.002 0.003 0.000 503 200 42 1150 ",
                "\"GET https://example.test/ HTTP/1.1\" \"Masked Agent/1.0\" TLS_AES_128_GCM_SHA256 TLSv1.3 ",
                "arn:aws:elasticloadbalancing:ap-northeast-2:000000000000:targetgroup/masked/0123456789abcdef ",
                "\"Root=1-masked\" \"example.test\" \"session-reused\" 1 2026-08-18T23:50:00.399000Z \"waf,forward\" \"-\" \"-\" \"10.0.0.10:8080\" \"200\" \"-\" \"-\"\n",
                "garbage line\n"
            )
            .as_bytes(),
        ),
    );
    let preview = preview_head(&alb, LogType::AlbAccess, &FieldMap::cloudtrail()).unwrap();
    assert_eq!((preview.records, preview.mapped), (2, 1));
    assert!(!preview.editable);
    assert_eq!(preview.event_names[0].name, "GET");
    // Positional tokens, spelled by position, labelled by the column they feed.
    assert_eq!(piece(&preview, "1").field.as_deref(), Some("event_time"));
    assert_eq!(piece(&preview, "3").field.as_deref(), Some("source_ip"));
    assert_eq!(
        piece(&preview, "8").field.as_deref(),
        Some("response.elb_status_code")
    );
    assert_eq!(
        piece(&preview, "12").value,
        "GET https://example.test/ HTTP/1.1"
    );
    assert_eq!(piece(&preview, "13").field.as_deref(), Some("user_agent"));
}

#[test]
fn a_head_cut_mid_record_keeps_the_complete_records() {
    // 256 KiB of head: only whole records count; a record cut in half is
    // neither a record nor an error.
    let big: Vec<_> = (0..3000).map(|_| cloudtrail_record("PutObject")).collect();
    let (_tmp, path) = cloudtrail_file(&big);

    let preview = preview_head(&path, LogType::CloudTrail, &FieldMap::cloudtrail()).unwrap();

    assert_eq!(preview.records, 200, "capped at the head record limit");
    assert_eq!(preview.mapped, 200);
}

#[test]
fn an_unrecognised_file_shows_its_first_line_as_bare_tokens() {
    // A Linux syslog dropped into the folder: not parsed, but the analyst
    // can see what it is instead of only "no signature".
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("auth.log.gz");
    write(
        &path,
        &gzip(b"Sep 15 10:00:01 host sshd[1]: Accepted publickey for u\n\nSep 15 10:00:02 host cron[2]: job\n"),
    );

    let preview = preview_head(&path, LogType::Unknown, &FieldMap::cloudtrail()).unwrap();

    assert_eq!((preview.records, preview.mapped), (2, 0));
    assert!(!preview.editable);
    assert!(preview.event_names.is_empty());
    let tokens: Vec<_> = preview.pieces.iter().map(|p| p.value.as_str()).collect();
    assert_eq!(tokens[..4], ["Sep", "15", "10:00:01", "host"]);
    assert!(preview
        .pieces
        .iter()
        .all(|p| p.field.is_none() && p.label.is_none()));
}
