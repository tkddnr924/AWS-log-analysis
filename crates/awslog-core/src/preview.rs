//! Pre-parse format preview (FR-4). The head of one file, read the way
//! detection reads it, broken into the pieces the parser will see: every
//! leaf of the first record (or every token of the first ALB line), each
//! labelled with the column it feeds — a built-in field, a rule path into
//! a payload column, or nothing. Alongside: how many head records parse,
//! which event names they carry, and every path the head holds
//! (docs/03 "포맷 카드").

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;
use specta::Type;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::detect::{self, DetectError, LogType};
use crate::mapping::{resolve, Field, FieldMap};

/// Records examined per file. The same order of magnitude as WebLog's 200
/// lines: enough to show what a file holds, far below a full parse.
pub const HEAD_RECORDS: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum PreviewError {
    #[error(transparent)]
    Read(#[from] DetectError),
    #[error("{0} 로그는 미리보기를 지원하지 않습니다")]
    Unsupported(&'static str),
}

/// A name and how many head records carried it.
#[derive(Debug, Clone, Serialize, Type)]
pub struct NameCount {
    pub name: String,
    pub count: u32,
}

/// One piece of the first record: a leaf path (or, for ALB, a token
/// position) and its value, with the column it feeds.
#[derive(Debug, Clone, Serialize, Type)]
pub struct Piece {
    pub path: String,
    pub value: String,
    /// `event_name`, `request.bucketName`, … ; `None` when nothing reads it.
    pub field: Option<String>,
    /// What to print above the piece: the built-in field's display name or
    /// the rule path.
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Type)]
pub struct HeadPreview {
    /// Records found in the head, up to [`HEAD_RECORDS`].
    pub records: u32,
    /// Of those, records with both a time and an event name.
    pub mapped: u32,
    /// Event names (ALB: HTTP methods; WAF: actions) in the head, most
    /// frequent first.
    pub event_names: Vec<NameCount>,
    pub pieces: Vec<Piece>,
    /// Every leaf path across the head with the records that had it, so the
    /// UI can list what the first record happens to lack.
    pub paths: Vec<NameCount>,
    /// Whether labels can be moved: only CloudTrail goes through the
    /// editable mapping; the other producers have fixed normalizers.
    pub editable: bool,
}

/// Previews the head of `path` as `log_type` under `map`.
pub fn preview_head(
    path: &Path,
    log_type: LogType,
    map: &FieldMap,
) -> Result<HeadPreview, PreviewError> {
    let (head, _) = detect::decoded_head(path)?;
    let text = String::from_utf8_lossy(&head);
    match log_type {
        LogType::CloudTrail => Ok(cloudtrail(&text, map)),
        LogType::WafAcl | LogType::ApigwAccess | LogType::NginxAccess => {
            Ok(ndjson(&text, log_type))
        }
        LogType::AlbAccess => Ok(alb(&text)),
        // Not an AWS log: still show what the file is, so "no signature"
        // is not the only thing the analyst learns about it.
        LogType::Unknown => Ok(unknown(&text)),
        other => Err(PreviewError::Unsupported(other.as_str())),
    }
}

/// Complete `Records` objects in the head, in order. A record cut off by
/// the head limit is left out.
fn cloudtrail_records(text: &str) -> Vec<Value> {
    let mut records = Vec::new();
    let Some(start) = text.find("\"Records\"") else {
        return records;
    };
    let mut cursor = start;
    while records.len() < HEAD_RECORDS {
        let Some(open) = text[cursor..].find('{') else {
            break;
        };
        let open = cursor + open;
        let Some(end) = detect::match_object_end(&text[open..]) else {
            break;
        };
        match serde_json::from_str::<Value>(&text[open..open + end]) {
            Ok(record) => records.push(record),
            Err(_) => break,
        }
        cursor = open + end;
    }
    records
}

fn cloudtrail(text: &str, map: &FieldMap) -> HeadPreview {
    let records = cloudtrail_records(text);
    let time_of = |record: &Value| {
        map.lookup_with(record, Field::EventTime, |v| {
            v.as_str()
                .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
        })
    };
    let name_of = |record: &Value| {
        map.lookup_with(record, Field::EventName, |v| v.as_str().map(str::to_owned))
    };
    let mut names = Counter::default();
    let mut paths = Counter::default();
    let mut mapped = 0;
    for record in &records {
        let name = name_of(record);
        if time_of(record).is_some() && name.is_some() {
            mapped += 1;
        }
        if let Some(name) = name {
            names.add(name);
        }
        for (path, _) in leaves(record) {
            paths.add(path);
        }
    }
    let pieces = records
        .first()
        .map(|first| labelled(first, &cloudtrail_labels(first, map)))
        .unwrap_or_default();
    HeadPreview {
        records: records.len() as u32,
        mapped,
        event_names: names.sorted(),
        pieces,
        paths: paths.sorted(),
        editable: true,
    }
}

/// Which raw path each built-in column reads from this record, plus the
/// payload columns' roots. The analyst's own assignments are placed first
/// so a path the defaults would also claim shows the label they gave it.
fn cloudtrail_labels(record: &Value, map: &FieldMap) -> Labels {
    let mut labels = Labels::default();
    let overridden = |field: Field| map.sources(field) != field.default_sources();
    let ordered = Field::ALL
        .iter()
        .copied()
        .filter(|f| overridden(*f))
        .chain(Field::ALL.iter().copied().filter(|f| !overridden(*f)));
    for field in ordered {
        let Some(path) = map
            .sources(field)
            .into_iter()
            .find(|path| resolve(record, path).is_some_and(|v| !v.is_null()))
        else {
            continue;
        };
        match field {
            Field::Request | Field::Response | Field::Resources => {
                labels.payload_roots.push((path.to_owned(), field));
            }
            _ => {
                labels
                    .fields
                    .entry(path.to_owned())
                    .or_insert((field.key().to_owned(), field.label().to_owned()));
            }
        }
    }
    labels
}

/// Raw path → column, for one record. `fields` names built-in columns;
/// `payload_roots` are the raw objects behind `request`/`response`/
/// `resources`, whose descendants are rule paths.
#[derive(Default)]
struct Labels {
    fields: HashMap<String, (String, String)>,
    payload_roots: Vec<(String, Field)>,
}

impl Labels {
    fn of(&self, path: &str) -> Option<(String, String)> {
        if let Some((field, label)) = self.fields.get(path) {
            return Some((field.clone(), label.clone()));
        }
        for (root, column) in &self.payload_roots {
            let rest = if path == root {
                None
            } else {
                path.strip_prefix(root.as_str())
                    .and_then(|rest| rest.strip_prefix('.'))
            };
            if path == root || rest.is_some() {
                let rule_path = match rest {
                    Some(rest) => format!("{}.{rest}", column.key()),
                    None => column.key().to_owned(),
                };
                let label = match rest {
                    Some(_) => rule_path.clone(),
                    None => column.label().to_owned(),
                };
                return Some((rule_path, label));
            }
        }
        None
    }
}

fn labelled(record: &Value, labels: &Labels) -> Vec<Piece> {
    leaves(record)
        .into_iter()
        .map(|(path, value)| {
            let (field, label) = labels.of(&path).unzip();
            Piece {
                path,
                value,
                field,
                label,
            }
        })
        .collect()
}

/// Every non-null leaf of a JSON value as `(path, text)`, paths spelled the
/// way the mapping and the rules spell them (`a.b.0.c`).
fn leaves(value: &Value) -> Vec<(String, String)> {
    fn walk(value: &Value, path: &mut String, out: &mut Vec<(String, String)>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let len = path.len();
                    if !path.is_empty() {
                        path.push('.');
                    }
                    path.push_str(key);
                    walk(child, path, out);
                    path.truncate(len);
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    let len = path.len();
                    if !path.is_empty() {
                        path.push('.');
                    }
                    path.push_str(&index.to_string());
                    walk(child, path, out);
                    path.truncate(len);
                }
            }
            Value::Null => {}
            Value::String(text) => out.push((path.clone(), text.clone())),
            other => out.push((path.clone(), other.to_string())),
        }
    }
    let mut out = Vec::new();
    walk(value, &mut String::new(), &mut out);
    out
}

/// The raw keys each NDJSON normalizer reads (docs/05 "NDJSON 로그 정규화"),
/// and the column each lands in. nginx paths are spelled from `_source`;
/// a record without that wrapper is matched with the prefix stripped.
fn ndjson_labels(log_type: LogType) -> &'static [(&'static str, &'static str)] {
    match log_type {
        LogType::WafAcl => &[
            ("timestamp", "event_time"),
            ("action", "event_name"),
            ("webaclId", "resources.web_acl_id"),
            ("terminatingRuleId", "response.terminating_rule_id"),
            ("terminatingRuleType", "response.terminating_rule_type"),
            ("httpSourceName", "resources.http_source_name"),
            ("httpSourceId", "resources.http_source_id"),
            ("responseCodeSent", "response.response_code_sent"),
            ("httpRequest.clientIp", "source_ip"),
            ("httpRequest.country", "request.country"),
            ("httpRequest.uri", "request.url"),
            ("httpRequest.args", "request.url"),
            ("httpRequest.httpVersion", "request.protocol"),
            ("httpRequest.httpMethod", "request.method"),
            ("httpRequest.requestId", "request.request_id"),
        ],
        LogType::ApigwAccess => &[
            ("request_time", "event_time"),
            ("http_method", "event_name"),
            ("ip", "source_ip"),
            ("user_agent", "user_agent"),
            ("status", "response.status"),
            ("path", "request.url"),
            ("protocol", "request.protocol"),
            ("request_id", "request.request_id"),
            ("response_length", "response.response_length"),
            ("integration_status", "response.integration_status"),
            ("integration_latency", "response.integration_latency"),
            ("api_id", "resources.api_id"),
            ("stage", "resources.stage"),
            ("resource_path", "resources.resource_path"),
        ],
        LogType::NginxAccess => &[
            ("_source.@timestamp", "event_time"),
            ("_source.birdview.request_method", "event_name"),
            ("_source.birdview.client_ip", "source_ip"),
            ("_source.birdview.http_user_agent", "user_agent"),
            ("_source.birdview.status", "response.status"),
            ("_source.birdview.host", "resources.host"),
            ("_source.birdview.request_uri", "request.url"),
            ("_source.birdview.server_protocol", "request.protocol"),
            ("_source.birdview.http_referer", "request.referer"),
            ("_source.birdview.bytes_sent", "response.bytes_sent"),
            (
                "_source.birdview.body_bytes_sent",
                "response.body_bytes_sent",
            ),
            ("_source.birdview.request_time", "response.request_time"),
            (
                "_source.birdview.upstream_response_time",
                "response.upstream_response_time",
            ),
            ("_source.birdview.remote_addr", "resources.remote_addr"),
            ("_source.service.name", "resources.service"),
            ("_source.service.environment", "resources.environment"),
            ("_source.trace.id", "request.trace_id"),
        ],
        _ => &[],
    }
}

fn ndjson(text: &str, log_type: LogType) -> HeadPreview {
    let mut names = Counter::default();
    let mut paths = Counter::default();
    let mut records = 0u32;
    let mut mapped = 0u32;
    let mut first: Option<Value> = None;
    for line in text.lines() {
        if records as usize >= HEAD_RECORDS {
            break;
        }
        let Ok(event) = crate::ndjson::normalize(log_type, line, 0, 0, false) else {
            continue;
        };
        // `normalize` parsed it already; parse again only for the pieces.
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        records += 1;
        if event.event_time.is_some() && event.event_name.is_some() {
            mapped += 1;
        }
        if let Some(name) = event.event_name {
            names.add(name);
        }
        for (path, _) in leaves(&value) {
            paths.add(path);
        }
        if first.is_none() {
            first = Some(value);
        }
    }
    let table = ndjson_labels(log_type);
    let pieces = first
        .as_ref()
        .map(|record| {
            leaves(record)
                .into_iter()
                .map(|(path, value)| {
                    let field = table
                        .iter()
                        .find(|(raw, _)| {
                            *raw == path || raw.strip_prefix("_source.") == Some(path.as_str())
                        })
                        .map(|(_, field)| (*field).to_owned());
                    Piece {
                        label: field.as_deref().map(display_label),
                        path,
                        value,
                        field,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    HeadPreview {
        records,
        mapped,
        event_names: names.sorted(),
        pieces,
        paths: paths.sorted(),
        editable: false,
    }
}

/// ALB access log positions (docs/03 "ALB 전체 파싱") and the column each
/// feeds. Positions absent here are not stored.
const ALB_LABELS: &[(usize, &str)] = &[
    (1, "event_time"),
    (2, "resources.load_balancer"),
    (3, "source_ip"),
    (4, "resources.target"),
    (5, "response.request_processing_time"),
    (6, "response.target_processing_time"),
    (7, "response.response_processing_time"),
    (8, "response.elb_status_code"),
    (9, "response.target_status_code"),
    (10, "response.received_bytes"),
    (11, "response.sent_bytes"),
    (12, "request.url"),
    (13, "user_agent"),
    (14, "resources.ssl_cipher"),
    (15, "resources.ssl_protocol"),
    (16, "resources.target_group_arn"),
    (17, "request.trace_id"),
    (18, "request.domain_name"),
    (19, "resources.chosen_cert_arn"),
    (21, "request.request_creation_time"),
    (22, "request.actions_executed"),
    (23, "request.redirect_url"),
    (24, "error_message"),
    (27, "response.classification"),
    (28, "response.classification_reason"),
];

fn alb(text: &str) -> HeadPreview {
    let mut names = Counter::default();
    let mut records = 0u32;
    let mut mapped = 0u32;
    let mut pieces = Vec::new();
    let mut fields = Vec::with_capacity(36);
    for line in text.lines() {
        if records as usize >= HEAD_RECORDS {
            break;
        }
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        records += 1;
        if let Ok(event) = crate::parse::normalize_alb(line, &mut fields, 0, 0, false) {
            mapped += 1;
            if let Some(method) = event.event_name {
                names.add(method);
            }
        }
        if pieces.is_empty() && crate::parse::tokenize_alb(line, &mut fields).is_ok() {
            pieces = fields
                .iter()
                .enumerate()
                .map(|(index, range)| {
                    let field = ALB_LABELS
                        .iter()
                        .find(|(at, _)| *at == index)
                        .map(|(_, field)| (*field).to_owned());
                    Piece {
                        path: index.to_string(),
                        value: line[range.clone()].to_owned(),
                        label: field.as_deref().map(display_label),
                        field,
                    }
                })
                .collect();
        }
    }
    HeadPreview {
        records,
        mapped,
        event_names: names.sorted(),
        pieces,
        paths: Vec::new(),
        editable: false,
    }
}

/// An unrecognised file: its first line as bare tokens, nothing labelled,
/// nothing parsed. Lines are counted so the card can still say how much
/// text there is.
fn unknown(text: &str) -> HeadPreview {
    let lines = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(HEAD_RECORDS)
        .count() as u32;
    let pieces = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| {
            line.split_whitespace()
                .enumerate()
                .map(|(index, token)| Piece {
                    path: index.to_string(),
                    value: token.to_owned(),
                    field: None,
                    label: None,
                })
                .collect()
        })
        .unwrap_or_default();
    HeadPreview {
        records: lines,
        mapped: 0,
        event_names: Vec::new(),
        pieces,
        paths: Vec::new(),
        editable: false,
    }
}

/// A built-in column shows its display name; a rule path shows itself.
fn display_label(field: &str) -> String {
    Field::from_key(field).map_or_else(|| field.to_owned(), |f| f.label().to_owned())
}

#[derive(Default)]
struct Counter(HashMap<String, u32>);

impl Counter {
    fn add(&mut self, name: String) {
        *self.0.entry(name).or_default() += 1;
    }

    /// Most frequent first, then by name, so the order is stable.
    fn sorted(self) -> Vec<NameCount> {
        let mut out: Vec<NameCount> = self
            .0
            .into_iter()
            .map(|(name, count)| NameCount { name, count })
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
        out
    }
}
