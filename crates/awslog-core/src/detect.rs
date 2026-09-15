//! FR-3: decide whether a candidate really is an AWS log by reading its head.
//! Extensions are not trusted (docs/03-log-detection.md).

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::bufread::MultiGzDecoder;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Bytes of decompressed head inspected per file. Detection must stay cheap:
/// the user has not pressed "parse" yet.
pub const HEAD_LIMIT: usize = 256 * 1024;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Compressed bytes scanned for member headers. Detection stays cheap.
const MEMBER_SCAN_LIMIT: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogType {
    CloudTrail,
    AlbAccess,
    WafAcl,
    ApigwAccess,
    NginxAccess,
    CloudTrailDigest,
    ConfigSnapshot,
    Unknown,
}

impl LogType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CloudTrail => "cloudtrail",
            Self::AlbAccess => "alb_access",
            Self::WafAcl => "waf_acl",
            Self::ApigwAccess => "apigw_access",
            Self::NginxAccess => "nginx_access",
            Self::CloudTrailDigest => "cloudtrail_digest",
            Self::ConfigSnapshot => "config_snapshot",
            Self::Unknown => "unknown",
        }
    }

    /// The inverse of [`Self::as_str`], for names that crossed IPC.
    pub fn parse(name: &str) -> Option<Self> {
        [
            Self::CloudTrail,
            Self::AlbAccess,
            Self::WafAcl,
            Self::ApigwAccess,
            Self::NginxAccess,
            Self::CloudTrailDigest,
            Self::ConfigSnapshot,
            Self::Unknown,
        ]
        .into_iter()
        .find(|t| t.as_str() == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Low,
    None,
}

/// Summary of the first record, shown before parsing (FR-4).
/// Deliberately not the whole record: IPC payloads stay small.
#[derive(Debug, Clone, Default)]
pub struct SampleRecord {
    /// The first record verbatim, so the mapping editor can resolve any path
    /// the user types instead of only the fields detection happens to read.
    pub raw: Option<String>,
    pub event_time: Option<String>,
    pub event_source: Option<String>,
    pub event_name: Option<String>,
    pub aws_region: Option<String>,
    pub user_identity_type: Option<String>,
    pub user_identity_arn: Option<String>,
    pub source_ip_address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub path: PathBuf,
    pub log_type: LogType,
    pub confidence: Confidence,
    pub sample: Option<SampleRecord>,
    /// Records seen in the decoded head, extrapolated when the head was cut off.
    pub record_count_estimate: Option<u64>,
    /// True when the file was larger than `HEAD_LIMIT`, so the count is a guess.
    pub estimated: bool,
    pub decoded_bytes: usize,
    /// Gzip member headers seen in the compressed head; approximate (see below).
    pub members_in_head: usize,
    /// Why detection failed or degraded; surfaced as a warning.
    pub note: Option<String>,
}

impl Detection {
    fn unknown(path: &Path, note: impl Into<String>) -> Self {
        Self {
            path: path.to_path_buf(),
            log_type: LogType::Unknown,
            confidence: Confidence::None,
            sample: None,
            record_count_estimate: None,
            estimated: false,
            decoded_bytes: 0,
            members_in_head: 0,
            note: Some(note.into()),
        }
    }
}

/// The decoded head of a gzip file, up to [`HEAD_LIMIT`] bytes, and whether
/// the stream ended early (a cut-off member still leaves usable bytes).
/// Shared by detection and the pre-parse preview so both look at the same
/// bytes.
pub fn decoded_head(path: &Path) -> Result<(Vec<u8>, bool), DetectError> {
    let io = |source| DetectError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(io)?;
    let mut decoder = MultiGzDecoder::new(BufReader::new(file));
    let mut head = Vec::with_capacity(HEAD_LIMIT.min(64 * 1024));
    let read_result = (&mut decoder)
        .take(HEAD_LIMIT as u64)
        .read_to_end(&mut head);
    match read_result {
        Ok(_) => Ok((head, false)),
        Err(_) if !head.is_empty() => Ok((head, true)),
        Err(source) => Err(io(source)),
    }
}

/// Inspects one candidate. Damage is reported in the result, never propagated
/// as an error, so one bad file cannot abort a scan (NFR-4).
pub fn detect_file(path: &Path) -> Result<Detection, DetectError> {
    let file = File::open(path).map_err(|source| DetectError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let compressed_len = file
        .metadata()
        .map_err(|source| DetectError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();

    let mut reader = BufReader::new(file);
    let mut magic = [0u8; 2];
    match reader.read_exact(&mut magic) {
        Ok(()) if magic == GZIP_MAGIC => {}
        Ok(()) => return Ok(Detection::unknown(path, "not gzip: bad magic bytes")),
        Err(_) => return Ok(Detection::unknown(path, "not gzip: file too short")),
    }

    let (head, truncated_stream) = match decoded_head(path) {
        Ok(head) => head,
        Err(DetectError::Io { source, .. }) => {
            return Ok(Detection::unknown(
                path,
                format!("gzip decode failed: {source}"),
            ))
        }
    };

    let head_cut = head.len() >= HEAD_LIMIT;
    let mut detection = classify(path, &head, head_cut);
    detection.decoded_bytes = head.len();
    detection.members_in_head = count_members_in_head(path).unwrap_or(0);

    if truncated_stream {
        detection.note = Some("gzip stream ended early; file may be truncated".into());
        if detection.log_type == LogType::Unknown {
            detection.confidence = Confidence::None;
        }
    }

    if detection.estimated {
        detection.record_count_estimate = detection.record_count_estimate.map(|seen| {
            estimate_total(
                seen,
                head.len(),
                uncompressed_len(path, compressed_len, detection.members_in_head),
            )
        });
    }

    Ok(detection)
}

/// Estimates the total record count from the gzip trailer.
///
/// Every gzip member ends with ISIZE: the uncompressed size mod 2^32. That is
/// exact for the common single-member file, so the estimate only depends on
/// the average record size measured in the decoded head — far more reliable
/// than assuming a compression ratio, which varies by orders of magnitude.
fn estimate_total(seen_in_head: u64, decoded: usize, uncompressed_len: Option<u64>) -> u64 {
    let (Some(total_bytes), true) = (uncompressed_len, decoded > 0 && seen_in_head > 0) else {
        return seen_in_head;
    };
    let bytes_per_record = decoded as f64 / seen_in_head as f64;
    ((total_bytes as f64) / bytes_per_record).round() as u64
}

/// Reads ISIZE from the last gzip member's trailer.
///
/// Limits, both of which make this return `None`:
/// - ISIZE covers only the **last** member, so concatenated files would be
///   undercounted; callers pass `members` and we decline when it is not 1.
/// - ISIZE is stored mod 2^32, so a member over 4 GiB wraps. A ratio above
///   ~1000:1 is treated as evidence of that wrap.
fn uncompressed_len(path: &Path, compressed_len: u64, members: usize) -> Option<u64> {
    if compressed_len < 18 || members > 1 {
        return None;
    }
    let mut file = File::open(path).ok()?;
    file.seek(SeekFrom::End(-4)).ok()?;
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf).ok()?;
    let isize_value = u32::from_le_bytes(buf) as u64;
    // A ratio above ~1000:1 means ISIZE almost certainly wrapped.
    (isize_value > 0 && isize_value / compressed_len.max(1) < 1000).then_some(isize_value)
}

fn classify(path: &Path, head: &[u8], head_cut: bool) -> Detection {
    let text = String::from_utf8_lossy(head);

    if let Some(sample) = text.lines().find_map(alb_sample_from_line) {
        let records_seen = text
            .lines()
            .filter(|line| alb_sample_from_line(line).is_some())
            .count() as u64;
        return Detection {
            path: path.to_path_buf(),
            log_type: LogType::AlbAccess,
            confidence: Confidence::High,
            sample: Some(sample),
            record_count_estimate: Some(records_seen),
            estimated: head_cut,
            decoded_bytes: head.len(),
            members_in_head: 0,
            note: None,
        };
    }

    // Line-delimited JSON (WAF, API Gateway, nginx exports): the first line
    // is one whole record, and its keys name the producer.
    if let Some((log_type, sample)) = text
        .lines()
        .next()
        .and_then(|line| serde_json::from_str::<Value>(line).ok())
        .and_then(|value| {
            crate::ndjson::classify(&value).map(|t| (t, crate::ndjson::sample(t, &value)))
        })
    {
        let records_seen = text.lines().filter(|line| line.starts_with('{')).count() as u64;
        return Detection {
            path: path.to_path_buf(),
            log_type,
            confidence: Confidence::High,
            sample: Some(sample),
            record_count_estimate: Some(records_seen),
            estimated: head_cut,
            decoded_bytes: head.len(),
            members_in_head: 0,
            note: None,
        };
    }

    // Take the first JSON document only: concatenated gzip members yield
    // `{...}{...}`, which is not a single valid document.
    let first_doc = serde_json::Deserializer::from_str(&text)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok);

    if let Some(value) = first_doc {
        return classify_value(path, &value, head.len(), false);
    }

    // The head was cut mid-document; recover the first record structurally.
    if let Some(sample) = first_record_from_partial(&text) {
        let records_seen = text.matches("\"eventVersion\"").count() as u64;
        return Detection {
            path: path.to_path_buf(),
            log_type: LogType::CloudTrail,
            confidence: Confidence::High,
            sample: Some(sample),
            record_count_estimate: Some(records_seen),
            estimated: head_cut,
            decoded_bytes: head.len(),
            members_in_head: 0,
            note: None,
        };
    }

    Detection::unknown(path, "no recognized AWS log signature")
}

fn alb_sample_from_line(line: &str) -> Option<SampleRecord> {
    let mut fields = line.split_whitespace();
    let protocol = fields.next()?;
    if !matches!(protocol, "http" | "https" | "h2" | "grpcs" | "ws" | "wss") {
        return None;
    }
    let event_time = fields.next()?;
    OffsetDateTime::parse(event_time, &Rfc3339).ok()?;
    if !fields.next()?.starts_with("app/") {
        return None;
    }
    let client = fields.next()?;
    let source_ip = client
        .strip_prefix('[')
        .and_then(|value| value.split_once("]:").map(|(host, _)| host))
        .or_else(|| client.rsplit_once(':').map(|(host, _)| host))?;

    Some(SampleRecord {
        raw: None,
        event_time: Some(event_time.to_owned()),
        event_source: Some("elasticloadbalancing.amazonaws.com".to_owned()),
        source_ip_address: Some(source_ip.to_owned()),
        ..Default::default()
    })
}

fn classify_value(path: &Path, value: &Value, decoded: usize, estimated: bool) -> Detection {
    let base = |log_type, confidence, sample, count| Detection {
        path: path.to_path_buf(),
        log_type,
        confidence,
        sample,
        record_count_estimate: count,
        estimated,
        decoded_bytes: decoded,
        members_in_head: 0,
        note: None,
    };

    if value.get("digestPublicKeyFingerprint").is_some() && value.get("logFiles").is_some() {
        return base(LogType::CloudTrailDigest, Confidence::High, None, None);
    }
    if let Some(items) = value.get("configurationItems").and_then(Value::as_array) {
        return base(
            LogType::ConfigSnapshot,
            Confidence::High,
            None,
            Some(items.len() as u64),
        );
    }
    if let Some(records) = value.get("Records").and_then(Value::as_array) {
        let count = Some(records.len() as u64);
        let Some(first) = records.first() else {
            return base(LogType::CloudTrail, Confidence::High, None, count);
        };
        let complete = ["eventVersion", "eventSource", "eventTime"]
            .iter()
            .all(|k| first.get(k).is_some());
        let confidence = if complete {
            Confidence::High
        } else {
            Confidence::Low
        };
        let sample = complete.then(|| sample_from(first));
        return base(LogType::CloudTrail, confidence, sample, count);
    }

    Detection::unknown(path, "no recognized AWS log signature")
}

/// Recovers the first record when the head was cut mid-document.
/// Matches braces instead of searching for `},`, which fails when the record
/// is the last one or contains nested objects.
fn first_record_from_partial(text: &str) -> Option<SampleRecord> {
    let start = text.find("\"Records\"")?;
    let obj_start = text[start..].find('{')? + start;
    let obj_end = match_object_end(&text[obj_start..])? + obj_start;
    let record: Value = serde_json::from_str(&text[obj_start..obj_end]).ok()?;
    record.get("eventVersion")?;
    Some(sample_from(&record))
}

/// Byte index just past the object starting at index 0, honouring strings
/// and escapes. `None` if the object never closes within `text`.
pub(crate) fn match_object_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn sample_from(record: &Value) -> SampleRecord {
    let string = |key: &str| record.get(key).and_then(Value::as_str).map(str::to_owned);
    let identity = |key: &str| {
        record
            .get("userIdentity")
            .and_then(|u| u.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };

    SampleRecord {
        raw: Some(record.to_string()),
        event_time: string("eventTime"),
        event_source: string("eventSource"),
        event_name: string("eventName"),
        aws_region: string("awsRegion"),
        user_identity_type: identity("type"),
        user_identity_arn: identity("arn"),
        source_ip_address: string("sourceIPAddress"),
    }
}

/// Counts gzip member headers within the first `MEMBER_SCAN_LIMIT` compressed
/// bytes. Bounded on purpose: detection runs before the user commits to
/// parsing, so it must not read multi-GB files (NFR-2).
///
/// The `1f 8b 08` signature can also occur by chance inside deflate data, so
/// this count is approximate: the 1 MiB cap can undercount and a chance
/// match inside deflate data can overcount. It is a UI hint, not a total.
fn count_members_in_head(path: &Path) -> Option<usize> {
    let file = File::open(path).ok()?;
    let mut head = Vec::new();
    file.take(MEMBER_SCAN_LIMIT as u64)
        .read_to_end(&mut head)
        .ok()?;

    let mut members = 0;
    let mut offset = 0;
    while offset + 2 < head.len() {
        if head[offset] == GZIP_MAGIC[0]
            && head[offset + 1] == GZIP_MAGIC[1]
            && head[offset + 2] == 0x08
        {
            members += 1;
            offset += 10; // Skip the fixed member header.
            continue;
        }
        offset += 1;
    }
    Some(members)
}
