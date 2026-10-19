//! FR-5: stream candidate files into the session store.
//! Records are decoded one at a time and flushed in batches so memory stays
//! flat regardless of input size (NFR-2).

use std::collections::{HashMap, HashSet};
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
use crate::payload::KeyCounter;
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

/// Parser threads. Each owns an appender holding up to
/// `store::APPENDER_FLUSH_BYTES`, so this also bounds parse memory. Past
/// four, per-file commits used to contend for DuckDB's locks; with one
/// appender per worker, eight cut a 1.09M-record CloudTrail corpus from
/// 16.9s (four) to 11.9s on an 8-core M1 (docs/02 "동시성").
const MAX_WORKERS: usize = 8;

struct ParseJob {
    file_id: u32,
    display: String,
    path: PathBuf,
    size_bytes: u64,
    log_type: LogType,
    detection_error: Option<String>,
}

/// What became of `jobs[job]`; `None` means cancelled before it started.
struct JobResult {
    job: usize,
    parsed: Option<Result<ParsedFile, String>>,
}

/// Parses every candidate under `root` into `store`.
///
/// Files decode concurrently through cloned handles to the same DuckDB
/// database. Workers take the next file as they free up, and each keeps one
/// bounded event batch and one appender for its whole share of the input.
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
    // One decoder per core, up to MAX_WORKERS. The pool is not shrunk to the
    // file count: a lone file still fans its line normalization out to the
    // idle threads (`parse_line_file`).
    let worker_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(2)
        .clamp(2, MAX_WORKERS);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .thread_name(|index| format!("awslog-parser-{index}"))
        .build()
        .map_err(|error| ParseError::WorkerPool(error.to_string()))?;

    // Head reads and gzip setup are independent. Preserve indexed order so
    // file IDs and later reports remain deterministic.
    let jobs: Vec<ParseJob> = pool.install(|| {
        chosen
            .into_par_iter()
            .map(|(file_id, display, candidate)| {
                let (log_type, detection_error) = match detect::detect_file(&candidate.path) {
                    Ok(detection) => (detection.log_type, None),
                    Err(error) => (
                        LogType::Unknown,
                        Some(crate::logging::redact(&error.to_string())),
                    ),
                };
                ParseJob {
                    file_id,
                    display,
                    path: candidate.path.clone(),
                    size_bytes: candidate.size_bytes,
                    log_type,
                    detection_error,
                }
            })
            .collect()
    });
    // Register before opening appenders. Metadata writes must not interleave
    // with DuckDB's parallel bulk append transactions.
    store.register_files(jobs.iter().map(|job| {
        (
            job.file_id,
            job.display.as_str(),
            job.size_bytes,
            job.log_type.as_str(),
        )
    }))?;
    let handles = (0..worker_count.min(jobs.len()))
        .map(|_| store.writer_handle())
        .collect::<Result<Vec<_>, StoreError>>()?;

    let next_job = AtomicUsize::new(0);
    let files_done = AtomicUsize::new(0);
    let records_parsed = AtomicU64::new(0);
    // Workers currently inside a file. While every pool thread has a file of
    // its own, fanning a batch out would only add scheduling cost.
    let busy = AtomicUsize::new(0);
    let spare_threads = || busy.load(Ordering::Relaxed) < worker_count;
    // Payload paths are counted where the batches are appended: one counter
    // per worker and log type, folded together after the run.
    type WorkerResult = (Vec<JobResult>, HashMap<&'static str, KeyCounter>);
    let completed: Vec<WorkerResult> = pool.install(|| {
        handles
            .into_par_iter()
            .map(|mut handle| -> Result<WorkerResult, StoreError> {
                // One appender per worker, not per file: DuckDB commits on
                // every appender flush, and a commit per small file (a
                // CloudTrail object holds ~700 records) went through the WAL
                // with an fsync and queued behind checkpoints — 63% of each
                // worker's time. Large commits write row groups directly.
                let mut writer = handle.event_writer()?;
                let mut keys: HashMap<&'static str, KeyCounter> = HashMap::new();
                let mut results = Vec::new();
                let mut json = Vec::new();
                loop {
                    let index = next_job.fetch_add(1, Ordering::Relaxed);
                    let Some(job) = jobs.get(index) else {
                        break;
                    };
                    let report_records = |count: u64| {
                        let records = records_parsed.fetch_add(count, Ordering::Relaxed) + count;
                        on_progress(Progress {
                            files_done: files_done.load(Ordering::Relaxed),
                            files_total: total,
                            records_parsed: records,
                        });
                    };
                    let mut sink = BatchSink {
                        writer: &mut writer,
                        on_stored: &report_records,
                        keys: keys.entry(job.log_type.as_str()).or_default(),
                    };
                    busy.fetch_add(1, Ordering::Relaxed);
                    let parsed = if cancelled(options) {
                        None
                    } else if let Some(note) = &job.detection_error {
                        Some(Err(note.clone()))
                    } else {
                        Some(match job.log_type {
                            LogType::AlbAccess => parse_line_file(
                                &job.path,
                                options,
                                &mut sink,
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
                                options,
                                &mut sink,
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
                            LogType::CloudTrail | LogType::Unknown => parse_cloudtrail_file(
                                &job.path,
                                job.file_id,
                                options,
                                &mut sink,
                                &mut json,
                            )
                            .map(|count| ParsedFile {
                                count,
                                malformed: 0,
                            }),
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
                    results.push(JobResult { job: index, parsed });
                }
                writer.finish()?;
                Ok((results, keys))
            })
            .collect::<Result<_, _>>()
    })?;
    let mut payload_keys: HashMap<&'static str, KeyCounter> = HashMap::new();
    let mut completed_jobs = Vec::with_capacity(jobs.len());
    for (results, keys) in completed {
        completed_jobs.extend(results);
        for (log_type, counter) in keys {
            payload_keys.entry(log_type).or_default().merge(counter);
        }
    }
    store.write_payload_keys(payload_keys.iter().flat_map(|(log_type, counter)| {
        counter.counts().map(move |(path, n)| (*log_type, path, n))
    }))?;

    let mut outcome = Outcome {
        cancelled: cancelled(options),
        ..Outcome::default()
    };
    // Reports follow file order whichever worker finished a file first.
    completed_jobs.sort_unstable_by_key(|result| result.job);
    let mut marks: Vec<(u32, &'static str, Option<u64>, Option<String>)> =
        Vec::with_capacity(completed_jobs.len());
    for result in completed_jobs {
        let job = &jobs[result.job];
        match result.parsed {
            None => {
                outcome.files_skipped += 1;
                marks.push((
                    job.file_id,
                    "skipped",
                    Some(0),
                    Some("cancelled before parse".to_owned()),
                ));
            }
            Some(Ok(ParsedFile { count: 0, .. })) => {
                outcome.files_skipped += 1;
                marks.push((
                    job.file_id,
                    "skipped",
                    Some(0),
                    Some("no supported log records".to_owned()),
                ));
            }
            Some(Ok(ParsedFile { count, malformed })) => {
                outcome.files_parsed += 1;
                outcome.records_parsed += count;
                let warning =
                    (malformed > 0).then(|| format!("{malformed} malformed ALB records skipped"));
                if let Some(reason) = &warning {
                    outcome.failures.push(FileFailure {
                        display_path: job.display.clone(),
                        reason: reason.clone(),
                    });
                }
                marks.push((job.file_id, "parsed", Some(count), warning));
            }
            Some(Err(note)) => {
                outcome.files_failed += 1;
                outcome.failures.push(FileFailure {
                    display_path: job.display.clone(),
                    reason: note.clone(),
                });
                marks.push((job.file_id, "failed", None, Some(note)));
            }
        }
    }
    store.mark_files(
        marks
            .iter()
            .map(|(file_id, status, count, note)| (*file_id, *status, *count, note.as_deref())),
    )?;

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

/// Decompressed bytes up to which a CloudTrail file is parsed from memory.
/// serde_json reads a slice far faster than an `io::Read`, which it pulls
/// one byte per call; most of a parse went there. CloudTrail objects are a
/// few MB, and a larger file streams on past this, so each worker holds at
/// most this much.
const IN_MEMORY_JSON_BYTES: u64 = 16 << 20;

/// Streams one CloudTrail file. Returns the record count, or a short failure
/// note. The `Records` array is consumed element by element: deserializing a
/// top-level document into `Value` would hold every record at once.
/// `buffer` is the worker's, reused across files.
fn parse_cloudtrail_file(
    path: &Path,
    file_id: u32,
    options: &ParseOptions,
    sink: &mut BatchSink<'_, '_>,
    buffer: &mut Vec<u8>,
) -> Result<u64, String> {
    use std::io::Read;

    let file = File::open(path).map_err(|e| format!("cannot open: {e}"))?;
    let mut decoder = BufReader::new(MultiGzDecoder::new(BufReader::new(file)));

    let mut sink = RecordSink {
        sink,
        options,
        batch: Vec::with_capacity(options.batch_size.min(4096)),
        file_id,
        count: 0,
        cancelled: false,
    };

    buffer.clear();
    let damage = match (&mut decoder)
        .take(IN_MEMORY_JSON_BYTES)
        .read_to_end(buffer)
    {
        // Larger than the cap: the rest streams on after what was read.
        Ok(_) if buffer.len() as u64 == IN_MEMORY_JSON_BYTES => sink.read_documents(
            &mut Deserializer::from_reader(std::io::Cursor::new(&buffer[..]).chain(decoder)),
        ),
        Ok(_) => sink.read_documents(&mut Deserializer::from_slice(buffer)),
        // A damaged stream still yields the records before the damage; the
        // cut-off JSON there reads as a clean end, so report the damage.
        Err(error) => {
            sink.read_documents(&mut Deserializer::from_slice(buffer));
            Some(crate::logging::redact(&error.to_string()))
        }
    };

    sink.flush()?;
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
    options: &ParseOptions,
    sink: &mut BatchSink<'_, '_>,
    kind: &str,
    spare_threads: &(dyn Fn() -> bool + Sync),
    normalize: impl Fn(&str, &mut Vec<Range<usize>>, u64) -> Result<NormalizedEvent, ()> + Sync,
) -> Result<ParsedFile, String> {
    let file = File::open(path).map_err(|error| format!("cannot open: {error}"))?;
    let decoder = MultiGzDecoder::new(BufReader::new(file));
    let mut reader = BufReader::new(decoder);
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
        flush_writer(&mut batch, sink)?;
    }

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

pub(crate) fn normalize_alb(
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

pub(crate) fn tokenize_alb(line: &str, fields: &mut Vec<Range<usize>>) -> Result<(), ()> {
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

/// Where a flushed batch goes: the worker's appender, the progress callback
/// and the payload-key counter for the file's log type.
struct BatchSink<'a, 'w> {
    writer: &'a mut EventWriter<'w>,
    on_stored: &'a dyn Fn(u64),
    keys: &'a mut KeyCounter,
}

/// Consumes `{"Records":[...]}` one element at a time, flushing batches as it
/// goes so peak memory is bounded by `batch_size`.
struct RecordSink<'a, 'b, 'w> {
    options: &'a ParseOptions,
    sink: &'a mut BatchSink<'b, 'w>,
    batch: Vec<NormalizedEvent>,
    file_id: u32,
    count: u64,
    cancelled: bool,
}

impl RecordSink<'_, '_, '_> {
    /// Reads top-level documents until the stream ends, the run is
    /// cancelled, or the JSON is damaged; returns the damage. Concatenated
    /// gzip members yield several documents in one stream.
    fn read_documents<'de, R: serde_json::de::Read<'de>>(
        &mut self,
        reader: &mut Deserializer<R>,
    ) -> Option<String> {
        use serde::de::DeserializeSeed;

        loop {
            match (DocumentSeed { sink: self }).deserialize(&mut *reader) {
                Ok(()) if self.cancelled => return None,
                Ok(()) => {}
                Err(e) if e.is_eof() => return None,
                Err(e) => return Some(crate::logging::redact(&e.to_string())),
            }
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
        flush_writer(&mut self.batch, self.sink)
    }
}

/// Visits one top-level object, streaming its `Records` array into the sink.
struct DocumentSeed<'a, 'b, 'c, 'w> {
    sink: &'a mut RecordSink<'b, 'c, 'w>,
}

impl<'de> serde::de::DeserializeSeed<'de> for DocumentSeed<'_, '_, '_, '_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> serde::de::Visitor<'de> for DocumentSeed<'_, '_, '_, '_> {
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

struct RecordsSeed<'a, 'b, 'c, 'w> {
    sink: &'a mut RecordSink<'b, 'c, 'w>,
}

impl<'de> serde::de::DeserializeSeed<'de> for RecordsSeed<'_, '_, '_, '_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> serde::de::Visitor<'de> for RecordsSeed<'_, '_, '_, '_> {
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

/// Appends one batch and records its payload paths. The counting happens
/// here, on the worker thread beside the append, so the normalizers stay
/// untouched and the batch-level fan-out (`parse_line_file`) needs no
/// shared state.
fn flush_writer(
    batch: &mut Vec<NormalizedEvent>,
    sink: &mut BatchSink<'_, '_>,
) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }
    let count = batch.len() as u64;
    for event in batch.iter() {
        sink.keys.record_event(event);
    }
    sink.writer
        .append(batch)
        .map_err(|error| format!("store write failed: {error}"))?;
    batch.clear();
    (sink.on_stored)(count);
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
