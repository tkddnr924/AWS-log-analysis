//! FR-5: stream candidate files into the session store.
//! Records are decoded one at a time and flushed in batches so memory stays
//! flat regardless of input size (NFR-2).

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use flate2::bufread::MultiGzDecoder;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Deserializer, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::detect::{self, LogType};
use crate::mapping::{self, Field, FieldMap};
use crate::model::NormalizedEvent;
use crate::scan::{self, ScanReport};
use crate::store::{EventWriter, Store, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error(transparent)]
    Scan(#[from] scan::ScanError),
    #[error("cannot create parser worker pool: {0}")]
    WorkerPool(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub struct ParseOptions {
    /// Rows buffered before a flush. Bounds peak memory per file.
    pub batch_size: usize,
    /// Cooperative cancellation; checked between files and batches.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Keep the original record for the rule engine's `raw` escape hatch.
    pub keep_raw: bool,
    /// Which JSON path feeds each column. Defaults to CloudTrail.
    pub mapping: FieldMap,
    /// Display paths the user kept in the review step. `None` parses every
    /// candidate; deselected files are never opened or registered.
    pub selected: Option<HashSet<String>>,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            batch_size: 10_000,
            cancel: None,
            keep_raw: true,
            mapping: FieldMap::cloudtrail(),
            selected: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub files_done: usize,
    pub files_total: usize,
    pub records_parsed: u64,
}

/// A file that could not be parsed, with the reason already redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFailure {
    pub display_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub files_parsed: usize,
    /// Readable but not an AWS log we handle.
    pub files_skipped: usize,
    /// Damaged input; reported per file instead of aborting (NFR-4).
    pub files_failed: usize,
    pub records_parsed: u64,
    pub cancelled: bool,
    /// Per-file damage, for `warnings.log` and the UI (NFR-4, FR-8).
    pub failures: Vec<FileFailure>,
}

struct ParseJob {
    file_id: u32,
    display: String,
    path: PathBuf,
    log_type: LogType,
    detection_error: Option<String>,
}

struct JobResult {
    file_id: u32,
    display: String,
    parsed: Option<Result<ParsedFile, String>>,
}

/// Parses every candidate under `root` into `store`.
///
/// Files decode concurrently through cloned handles to the same DuckDB
/// database. Each worker keeps one bounded event batch and one file appender.
pub fn run(
    root: &Path,
    store: &mut Store,
    options: &ParseOptions,
    on_progress: &(dyn Fn(Progress) + Sync),
) -> Result<Outcome, ParseError> {
    let report: ScanReport = scan::scan_dir(root)?;
    let chosen: Vec<(u32, String, &scan::Candidate)> = report
        .candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let display = crate::report::relative(root, &candidate.path);
            (index as u32, display, candidate)
        })
        .filter(|(_, display, _)| match &options.selected {
            Some(set) => set.contains(display),
            None => true,
        })
        .collect();
    let total = chosen.len();
    // Four decoders keep gzip/JSON work parallel without multiplying each
    // worker's bounded batch or overwhelming DuckDB's single database file.
    // The pool is not shrunk to the file count: a lone file still fans its
    // line normalization out to the idle threads (`parse_line_file`).
    let worker_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(2)
        .clamp(2, 4);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .thread_name(|index| format!("awslog-parser-{index}"))
        .build()
        .map_err(|error| ParseError::WorkerPool(error.to_string()))?;

    // Head reads and gzip setup are independent. Preserve indexed order so
    // file IDs and later reports remain deterministic.
    let detected: Vec<_> = pool.install(|| {
        chosen
            .into_par_iter()
            .map(|(file_id, display, candidate)| {
                let detection = detect::detect_file(&candidate.path);
                (
                    file_id,
                    display,
                    candidate.path.clone(),
                    candidate.size_bytes,
                    detection,
                )
            })
            .collect()
    });
    // Register before opening appenders. Metadata writes must not interleave
    // with DuckDB's parallel bulk append transactions.
    let mut buckets: Vec<Vec<ParseJob>> = (0..worker_count).map(|_| Vec::new()).collect();
    for (index, (file_id, display, path, size_bytes, detection)) in detected.into_iter().enumerate()
    {
        let (log_type, detection_error) = match detection {
            Ok(detection) => (detection.log_type, None),
            Err(error) => (
                LogType::Unknown,
                Some(crate::logging::redact(&error.to_string())),
            ),
        };
        store.register_file(file_id, &display, size_bytes, log_type.as_str())?;
        buckets[index % worker_count].push(ParseJob {
            file_id,
            display,
            path,
            log_type,
            detection_error,
        });
    }
    let workers = buckets
        .into_iter()
        .filter(|jobs| !jobs.is_empty())
        .map(|jobs| store.writer_handle().map(|writer| (writer, jobs)))
        .collect::<Result<Vec<_>, StoreError>>()?;

    let files_done = AtomicUsize::new(0);
    let records_parsed = AtomicU64::new(0);
    // Workers currently inside a file. While every pool thread has a file of
    // its own, fanning a batch out would only add scheduling cost.
    let busy = AtomicUsize::new(0);
    let spare_threads = || busy.load(Ordering::Relaxed) < worker_count;
    let completed: Vec<JobResult> = pool
        .install(|| {
            workers
                .into_par_iter()
                .map(|(mut writer, jobs)| {
                    jobs.into_iter()
                        .map(|job| {
                            let report_records = |count: u64| {
                                let records =
                                    records_parsed.fetch_add(count, Ordering::Relaxed) + count;
                                on_progress(Progress {
                                    files_done: files_done.load(Ordering::Relaxed),
                                    files_total: total,
                                    records_parsed: records,
                                });
                            };
                            busy.fetch_add(1, Ordering::Relaxed);
                            let parsed = if cancelled(options) {
                                None
                            } else if let Some(note) = job.detection_error {
                                Some(Err(note))
                            } else {
                                Some(match job.log_type {
                                    LogType::AlbAccess => parse_line_file(
                                        &job.path,
                                        &mut writer,
                                        options,
                                        &report_records,
                                        "ALB",
                                        &spare_threads,
                                        |line, fields, index| {
                                            normalize_alb(
                                                line,
                                                fields,
                                                job.file_id,
                                                index,
                                                options.keep_raw,
                                            )
                                        },
                                    ),
                                    log_type @ (LogType::WafAcl
                                    | LogType::ApigwAccess
                                    | LogType::NginxAccess) => parse_line_file(
                                        &job.path,
                                        &mut writer,
                                        options,
                                        &report_records,
                                        log_type.as_str(),
                                        &spare_threads,
                                        |line, _, index| {
                                            crate::ndjson::normalize(
                                                log_type,
                                                line,
                                                job.file_id,
                                                index,
                                                options.keep_raw,
                                            )
                                        },
                                    ),
                                    LogType::CloudTrail | LogType::Unknown => {
                                        parse_cloudtrail_file(
                                            &job.path,
                                            job.file_id,
                                            &mut writer,
                                            options,
                                            &report_records,
                                        )
                                        .map(|count| {
                                            ParsedFile {
                                                count,
                                                malformed: 0,
                                            }
                                        })
                                    }
                                    LogType::CloudTrailDigest | LogType::ConfigSnapshot => {
                                        Ok(ParsedFile::default())
                                    }
                                })
                            };
                            busy.fetch_sub(1, Ordering::Relaxed);
                            let done = files_done.fetch_add(1, Ordering::Relaxed) + 1;
                            on_progress(Progress {
                                files_done: done,
                                files_total: total,
                                records_parsed: records_parsed.load(Ordering::Relaxed),
                            });
                            JobResult {
                                file_id: job.file_id,
                                display: job.display,
                                parsed,
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();

    let mut outcome = Outcome {
        cancelled: cancelled(options),
        ..Outcome::default()
    };
    for result in completed {
        match result.parsed {
            None => {
                outcome.files_skipped += 1;
                store.mark_file(
                    result.file_id,
                    "skipped",
                    Some(0),
                    Some("cancelled before parse"),
                )?;
            }
            Some(Ok(ParsedFile { count: 0, .. })) => {
                outcome.files_skipped += 1;
                store.mark_file(
                    result.file_id,
                    "skipped",
                    Some(0),
                    Some("no supported log records"),
                )?;
            }
            Some(Ok(ParsedFile { count, malformed })) => {
                outcome.files_parsed += 1;
                outcome.records_parsed += count;
                let warning =
                    (malformed > 0).then(|| format!("{malformed} malformed ALB records skipped"));
                store.mark_file(result.file_id, "parsed", Some(count), warning.as_deref())?;
                if let Some(reason) = warning {
                    outcome.failures.push(FileFailure {
                        display_path: result.display,
                        reason,
                    });
                }
            }
            Some(Err(note)) => {
                outcome.files_failed += 1;
                store.mark_file(result.file_id, "failed", None, Some(&note))?;
                outcome.failures.push(FileFailure {
                    display_path: result.display,
                    reason: note,
                });
            }
        }
    }

    Ok(outcome)
}

fn cancelled(options: &ParseOptions) -> bool {
    options
        .cancel
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::Relaxed))
}

#[derive(Debug, Default)]
struct ParsedFile {
    count: u64,
    malformed: u64,
}

/// Streams one CloudTrail file. Returns the record count, or a short failure
/// note. The `Records` array is consumed element by element: deserializing a
/// top-level document into `Value` would hold the whole file in memory.
fn parse_cloudtrail_file(
    path: &Path,
    file_id: u32,
    store: &mut Store,
    options: &ParseOptions,
    on_stored: &dyn Fn(u64),
) -> Result<u64, String> {
    let file = File::open(path).map_err(|e| format!("cannot open: {e}"))?;
    let decoder = MultiGzDecoder::new(BufReader::new(file));
    let mut reader = Deserializer::from_reader(BufReader::new(decoder));

    let mut sink = RecordSink {
        writer: store
            .event_writer()
            .map_err(|error| format!("store writer failed: {error}"))?,
        options,
        on_stored,
        batch: Vec::with_capacity(options.batch_size.min(4096)),
        file_id,
        count: 0,
        cancelled: false,
    };

    // Concatenated gzip members yield several top-level documents in one
    // stream; keep reading until the stream ends.
    let mut damage = None;
    loop {
        match sink.deserialize_document(&mut reader) {
            Ok(true) => {}
            Ok(false) => break,
            Err(message) => {
                damage = Some(message);
                break;
            }
        }
        if sink.cancelled {
            break;
        }
    }

    sink.flush()?;
    sink.writer
        .finish()
        .map_err(|error| format!("store write failed: {error}"))?;
    // Trailing damage after usable records is reported, not fatal.
    match damage {
        Some(message) if sink.count == 0 => Err(message),
        _ => Ok(sink.count),
    }
}

/// Streams one line-per-record file (ALB text, NDJSON). `normalize` turns a
/// line into an event or `Err(())` for a malformed one, which is counted and
/// skipped; a file with no valid record at all fails.
///
/// Inflate and the appender are serial per file, but normalizing a batch of
/// lines fans out over the worker pool while `spare_threads` says some are
/// idle: a lone big NDJSON file spent half its time in `serde_json` on one
/// thread (9.6s → 6.4s). With every worker on a file of its own the fan-out
/// only cost scheduling (~6% on a 40-file ALB set), so it stays sequential.
fn parse_line_file(
    path: &Path,
    store: &mut Store,
    options: &ParseOptions,
    on_stored: &dyn Fn(u64),
    kind: &str,
    spare_threads: &(dyn Fn() -> bool + Sync),
    normalize: impl Fn(&str, &mut Vec<Range<usize>>, u64) -> Result<NormalizedEvent, ()> + Sync,
) -> Result<ParsedFile, String> {
    let file = File::open(path).map_err(|error| format!("cannot open: {error}"))?;
    let decoder = MultiGzDecoder::new(BufReader::new(file));
    let mut reader = BufReader::new(decoder);
    let mut writer = store
        .event_writer()
        .map_err(|error| format!("store writer failed: {error}"))?;
    // Line buffers are reused across batches; `filled` bounds the live ones.
    let mut lines: Vec<String> = Vec::new();
    let mut batch = Vec::with_capacity(options.batch_size.min(4096));
    let mut parsed = ParsedFile::default();
    let mut record_base = 0u64;
    let mut eof = false;

    while !eof && !cancelled(options) {
        let mut filled = 0;
        while filled < options.batch_size {
            if lines.len() == filled {
                lines.push(String::new());
            }
            let line = &mut lines[filled];
            line.clear();
            let bytes = reader
                .read_line(line)
                .map_err(|error| crate::logging::redact(&format!("gzip read failed: {error}")))?;
            if bytes == 0 {
                eof = true;
                break;
            }
            line.truncate(line.trim_end_matches(['\r', '\n']).len());
            if !line.is_empty() {
                filled += 1;
            }
        }

        // One split of the whole batch keeps it on this thread.
        let min_split = if spare_threads() { 1 } else { filled.max(1) };
        let events: Vec<Result<NormalizedEvent, ()>> = lines[..filled]
            .par_iter()
            .with_min_len(min_split)
            .enumerate()
            .map_init(
                || Vec::with_capacity(36),
                |fields, (offset, line)| normalize(line, fields, record_base + offset as u64),
            )
            .collect();
        record_base += filled as u64;
        for event in events {
            match event {
                Ok(event) => {
                    batch.push(event);
                    parsed.count += 1;
                }
                Err(()) => parsed.malformed += 1,
            }
        }
        flush_writer(&mut writer, &mut batch, on_stored)?;
    }

    writer
        .finish()
        .map_err(|error| format!("store write failed: {error}"))?;
    if parsed.count == 0 && parsed.malformed > 0 {
        return Err(format!(
            "no valid {kind} records; {} malformed records",
            parsed.malformed
        ));
    }
    Ok(parsed)
}

#[derive(Serialize)]
struct AlbRequest<'a> {
    method: Option<&'a str>,
    url: Option<&'a str>,
    protocol: Option<&'a str>,
    trace_id: Option<&'a str>,
    domain_name: Option<&'a str>,
    request_creation_time: Option<&'a str>,
    actions_executed: Option<&'a str>,
    redirect_url: Option<&'a str>,
}

#[derive(Serialize)]
struct AlbResponse<'a> {
    request_processing_time: Option<f64>,
    target_processing_time: Option<f64>,
    response_processing_time: Option<f64>,
    elb_status_code: Option<u16>,
    target_status_code: Option<u16>,
    received_bytes: Option<u64>,
    sent_bytes: Option<u64>,
    error_reason: Option<&'a str>,
    classification: Option<&'a str>,
    classification_reason: Option<&'a str>,
}

#[derive(Serialize)]
struct AlbResources<'a> {
    load_balancer: &'a str,
    target: Option<&'a str>,
    target_group_arn: Option<&'a str>,
    ssl_cipher: Option<&'a str>,
    ssl_protocol: Option<&'a str>,
    chosen_cert_arn: Option<&'a str>,
}

#[derive(Serialize)]
struct AlbRaw<'a> {
    log_type: &'static str,
    line: &'a str,
}

fn normalize_alb(
    line: &str,
    fields: &mut Vec<Range<usize>>,
    file_id: u32,
    record_index: u64,
    keep_raw: bool,
) -> Result<NormalizedEvent, ()> {
    tokenize_alb(line, fields)?;
    if fields.len() < 17 {
        return Err(());
    }

    let value = |index| field(line, fields, index).ok_or(());
    let protocol = value(0)?;
    if !matches!(protocol, "http" | "https" | "h2" | "grpcs" | "ws" | "wss") {
        return Err(());
    }
    let event_time = OffsetDateTime::parse(value(1)?, &Rfc3339).map_err(|_| ())?;
    let load_balancer = value(2)?;
    if !load_balancer.starts_with("app/") {
        return Err(());
    }
    let source_ip = endpoint_host(value(3)?).ok_or(())?;
    let target = present(value(4)?);
    let request = present(value(12)?);
    let user_agent = present(value(13)?);
    let target_group_arn = present(value(16)?);

    let (method, url, request_protocol) = request
        .map(|request| {
            let mut parts = request.splitn(3, ' ');
            (parts.next(), parts.next(), parts.next())
        })
        .unwrap_or((None, None, None));
    let status = optional_parse::<u16>(field(line, fields, 8));
    let target_status = optional_parse::<u16>(field(line, fields, 9));
    let error_reason = field(line, fields, 24).and_then(present);
    let classification = field(line, fields, 27).and_then(present);
    let classification_reason = field(line, fields, 28).and_then(present);
    let error_message = error_reason.or(classification_reason);
    let region = target_group_arn.and_then(|arn| arn.split(':').nth(3));
    let account_id = target_group_arn.and_then(|arn| arn.split(':').nth(4));

    let request_json = serde_json::to_string(&AlbRequest {
        method,
        url,
        protocol: request_protocol,
        trace_id: field(line, fields, 17).and_then(present),
        domain_name: field(line, fields, 18).and_then(present),
        request_creation_time: field(line, fields, 21).and_then(present),
        actions_executed: field(line, fields, 22).and_then(present),
        redirect_url: field(line, fields, 23).and_then(present),
    })
    .map_err(|_| ())?;
    let response_json = serde_json::to_string(&AlbResponse {
        request_processing_time: optional_parse::<f64>(field(line, fields, 5)),
        target_processing_time: optional_parse::<f64>(field(line, fields, 6)),
        response_processing_time: optional_parse::<f64>(field(line, fields, 7)),
        elb_status_code: status,
        target_status_code: target_status,
        received_bytes: optional_parse::<u64>(field(line, fields, 10)),
        sent_bytes: optional_parse::<u64>(field(line, fields, 11)),
        error_reason,
        classification,
        classification_reason,
    })
    .map_err(|_| ())?;
    let resources_json = serde_json::to_string(&AlbResources {
        load_balancer,
        target,
        target_group_arn,
        ssl_cipher: field(line, fields, 14).and_then(present),
        ssl_protocol: field(line, fields, 15).and_then(present),
        chosen_cert_arn: field(line, fields, 19).and_then(present),
    })
    .map_err(|_| ())?;
    let raw = keep_raw
        .then(|| {
            serde_json::to_string(&AlbRaw {
                log_type: "alb_access",
                line,
            })
        })
        .transpose()
        .map_err(|_| ())?;

    Ok(NormalizedEvent {
        file_id,
        record_index,
        event_time: Some(event_time),
        event_source: Some("elasticloadbalancing.amazonaws.com".to_owned()),
        event_name: method.map(str::to_owned),
        aws_region: region.map(str::to_owned),
        account_id: account_id.map(str::to_owned),
        source_ip: Some(source_ip.to_owned()),
        user_agent: user_agent.map(str::to_owned),
        identity_type: None,
        identity_arn: None,
        identity_name: None,
        mfa_authenticated: None,
        error_code: status
            .filter(|status| *status >= 400)
            .map(|status| format!("HTTP {status}")),
        error_message: error_message.map(str::to_owned),
        read_only: method.map(|method| matches!(method, "GET" | "HEAD" | "OPTIONS")),
        management_event: Some(false),
        request: Some(request_json),
        response: Some(response_json),
        resources: Some(resources_json),
        raw,
    })
}

fn tokenize_alb(line: &str, fields: &mut Vec<Range<usize>>) -> Result<(), ()> {
    fields.clear();
    let bytes = line.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor == bytes.len() {
            break;
        }

        if bytes[cursor] == b'"' {
            cursor += 1;
            let start = cursor;
            let mut escaped = false;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    _ if escaped => escaped = false,
                    b'\\' => escaped = true,
                    b'"' => break,
                    _ => {}
                }
                cursor += 1;
            }
            if cursor == bytes.len() {
                return Err(());
            }
            fields.push(start..cursor);
            cursor += 1;
            if cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
                return Err(());
            }
        } else {
            let start = cursor;
            while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            fields.push(start..cursor);
        }
    }
    Ok(())
}

fn field<'a>(line: &'a str, fields: &[Range<usize>], index: usize) -> Option<&'a str> {
    fields.get(index).map(|range| &line[range.clone()])
}

fn present(value: &str) -> Option<&str> {
    (value != "-").then_some(value)
}

fn optional_parse<T: std::str::FromStr>(value: Option<&str>) -> Option<T> {
    value.and_then(present).and_then(|value| value.parse().ok())
}

fn endpoint_host(endpoint: &str) -> Option<&str> {
    endpoint
        .strip_prefix('[')
        .and_then(|value| value.split_once("]:").map(|(host, _)| host))
        .or_else(|| endpoint.rsplit_once(':').map(|(host, _)| host))
}

/// Consumes `{"Records":[...]}` one element at a time, flushing batches as it
/// goes so peak memory is bounded by `batch_size`.
struct RecordSink<'a> {
    writer: EventWriter<'a>,
    options: &'a ParseOptions,
    on_stored: &'a dyn Fn(u64),
    batch: Vec<NormalizedEvent>,
    file_id: u32,
    count: u64,
    cancelled: bool,
}

impl RecordSink<'_> {
    /// Reads one top-level document. `Ok(false)` means the stream ended.
    fn deserialize_document<R: std::io::Read>(
        &mut self,
        reader: &mut Deserializer<serde_json::de::IoRead<R>>,
    ) -> Result<bool, String> {
        use serde::de::DeserializeSeed;

        match (DocumentSeed { sink: self }).deserialize(&mut *reader) {
            Ok(()) => Ok(true),
            Err(e) if e.is_eof() => Ok(false),
            Err(e) => Err(crate::logging::redact(&e.to_string())),
        }
    }

    fn push(&mut self, record: &Value) -> Result<(), String> {
        self.batch.push(normalize(
            record,
            self.file_id,
            self.count,
            self.options.keep_raw,
            &self.options.mapping,
        ));
        self.count += 1;
        if self.batch.len() >= self.options.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), String> {
        flush_writer(&mut self.writer, &mut self.batch, self.on_stored)
    }
}

/// Visits one top-level object, streaming its `Records` array into the sink.
struct DocumentSeed<'a, 'b> {
    sink: &'a mut RecordSink<'b>,
}

impl<'de> serde::de::DeserializeSeed<'de> for DocumentSeed<'_, '_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> serde::de::Visitor<'de> for DocumentSeed<'_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("an AWS log document")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "Records" {
                map.next_value_seed(RecordsSeed { sink: self.sink })?;
            } else {
                // Skip sibling keys without building their values.
                map.next_value::<serde::de::IgnoredAny>()?;
            }
            if self.sink.cancelled {
                return Ok(());
            }
        }
        Ok(())
    }
}

struct RecordsSeed<'a, 'b> {
    sink: &'a mut RecordSink<'b>,
}

impl<'de> serde::de::DeserializeSeed<'de> for RecordsSeed<'_, '_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> serde::de::Visitor<'de> for RecordsSeed<'_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a record array")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        use serde::de::Error as _;

        // One record at a time: the array never exists as a whole.
        while let Some(record) = seq.next_element::<Value>()? {
            if cancelled(self.sink.options) {
                self.sink.cancelled = true;
                return Ok(());
            }
            if let Err(message) = self.sink.push(&record) {
                return Err(A::Error::custom(message));
            }
        }
        Ok(())
    }
}

fn flush_writer(
    writer: &mut EventWriter<'_>,
    batch: &mut Vec<NormalizedEvent>,
    on_stored: &dyn Fn(u64),
) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }
    let count = batch.len() as u64;
    writer
        .append(batch)
        .map_err(|error| format!("store write failed: {error}"))?;
    batch.clear();
    on_stored(count);
    Ok(())
}

fn normalize(
    record: &Value,
    file_id: u32,
    record_index: u64,
    keep_raw: bool,
    map: &FieldMap,
) -> NormalizedEvent {
    // Every column goes through the mapping, so an override reaches the store
    // without touching this function.
    let text = |field: Field| {
        map.lookup_with(record, field, |v| match v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
    };
    let flag = |field: Field| map.lookup_with(record, field, mapping::as_bool);
    // Service-specific shapes stay as JSON text; rules address them dynamically.
    let json = |field: Field| map.lookup(record, field).map(|v| v.to_string());

    NormalizedEvent {
        file_id,
        record_index,
        // Time coercion also sits inside the fallback: a path holding a
        // non-RFC3339 string must not shadow a later, valid one.
        event_time: map.lookup_with(record, Field::EventTime, |v| {
            v.as_str()
                .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
        }),
        event_source: text(Field::EventSource),
        event_name: text(Field::EventName),
        aws_region: text(Field::AwsRegion),
        account_id: text(Field::AccountId),
        source_ip: text(Field::SourceIp),
        user_agent: text(Field::UserAgent),
        identity_type: text(Field::IdentityType),
        identity_arn: text(Field::IdentityArn),
        identity_name: text(Field::IdentityName),
        mfa_authenticated: flag(Field::MfaAuthenticated),
        error_code: text(Field::ErrorCode),
        error_message: text(Field::ErrorMessage),
        read_only: flag(Field::ReadOnly),
        management_event: flag(Field::ManagementEvent),
        request: json(Field::Request),
        response: json(Field::Response),
        resources: json(Field::Resources),
        raw: keep_raw.then(|| record.to_string()),
    }
}
