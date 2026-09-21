//! DuckDB session store. One case = one database file
//! (docs/05-data-model.md).

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use duckdb::types::{TimeUnit, Value};
use duckdb::{params, Appender, Connection};
use time::OffsetDateTime;

use crate::model::NormalizedEvent;
use crate::rule::{Condition, FieldCondition, Literal, Op, Rule};

const SCHEMA: &str = include_str!("store/schema.sql");

/// The summary a results row shows, projected from `events e`: the id, the
/// time twice (raw for storing and comparing, KST text for display), then
/// the display columns. HTTP-style fields (ALB, WAF, API Gateway, nginx)
/// come out of the JSON bodies; CloudTrail rows get NULLs there.
const EVENT_SUMMARY_COLUMNS: &str = "e.event_id, epoch_us(e.event_time),
    strftime(e.event_time + INTERVAL 9 HOUR, '%Y-%m-%d %H:%M:%S.%g'),
    e.event_name, e.event_source, e.identity_arn, e.source_ip,
    json_extract_string(e.request, '$.url'),
    coalesce(json_extract_string(e.response, '$.elb_status_code'),
             json_extract_string(e.response, '$.status')),
    coalesce(json_extract_string(e.resources, '$.target'),
             json_extract_string(e.resources, '$.host')),
    e.user_agent, e.aws_region, e.error_code,
    json_extract_string(e.resources, '$[0].ARN'),
    json_extract_string(e.request, '$.country'),
    json_extract_string(e.response, '$.terminating_rule_id'),
    json_extract_string(e.request, '$.method')";

/// The same summary read back from `rule_matches e`, where it was stored
/// by [`Store::append_match_batch`]. Same positions as
/// [`EVENT_SUMMARY_COLUMNS`] so one reader serves both.
const MATCH_SUMMARY_COLUMNS: &str = "e.event_id, epoch_us(e.event_time),
    strftime(e.event_time + INTERVAL 9 HOUR, '%Y-%m-%d %H:%M:%S.%g'),
    e.event_name, e.event_source, e.identity_arn, e.source_ip,
    e.url, e.status, e.target, e.user_agent, e.aws_region, e.error_code,
    e.resource, e.country, e.rule, e.method";

/// Ids per `IN (...)` list when fetching summaries by event id. The primary
/// key index answers a constant list in a few milliseconds regardless of
/// case size; a prepared `event_id = ?` per id cost 0.5 ms each (12M-row
/// bench, plan 260915).
const SUMMARY_LOOKUP_BATCH: usize = 1_000;

/// Rows per batch when rebuilding an older case's match table on open.
const MIGRATION_BATCH: u64 = 10_000;

/// Narrows `events e` to one log type through its source file.
const EVENT_TYPE_FILTER: &str = "AND e.file_id IN (SELECT file_id FROM files WHERE log_type = ?)";
/// Narrows `rule_matches e`, which carries the type itself.
const MATCH_TYPE_FILTER: &str = "AND e.log_type = ?";

/// Event columns in the order `scan_events` reads them (after `event_id`,
/// `file_id`, `record_index`).
const EVENT_COLUMNS: [&str; 18] = [
    "event_source",
    "event_name",
    "aws_region",
    "account_id",
    "source_ip",
    "user_agent",
    "identity_type",
    "identity_arn",
    "identity_name",
    "mfa_authenticated",
    "error_code",
    "error_message",
    "read_only",
    "management_event",
    "request",
    "response",
    "resources",
    "raw",
];

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] duckdb::Error),
    #[error("case metadata missing from {0}")]
    MissingMeta(String),
    #[error("cannot write case.json: {0}")]
    CaseJson(#[source] serde_json::Error),
    #[error("file {file_id} exceeds the 32-bit record index range")]
    RecordIndexOverflow { file_id: u32 },
    // Shown under the date inputs as-is; the frontend keys on the prefix.
    #[error("존재하지 않는 날짜·시각입니다: {0:?}")]
    BadDateTime(String),
    #[error("rule evaluation failed: {0}")]
    RuleRun(String),
    // A run the user walked away from. Not a failure: the work is simply
    // not recorded, and the next attempt starts over.
    #[error("작업이 취소되었습니다")]
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseStatus {
    Running,
    Done,
    Cancelled,
    Failed,
}

impl CaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CaseStatus::Running => "running",
            CaseStatus::Done => "done",
            CaseStatus::Cancelled => "cancelled",
            CaseStatus::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "done" => CaseStatus::Done,
            "cancelled" => CaseStatus::Cancelled,
            "failed" => CaseStatus::Failed,
            _ => CaseStatus::Running,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaseMeta {
    pub case_id: String,
    pub input_dir: String,
    pub status: CaseStatus,
    pub app_version: String,
}

/// One stored event, read back for verification and the results view.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub event_id: u64,
    pub record_index: u64,
    pub event_name: Option<String>,
    pub identity_arn: Option<String>,
    pub mfa_authenticated: Option<bool>,
    pub raw: Option<String>,
}

/// A results row plus the raw time it was sorted and filtered by, which the
/// match table stores as a `TIMESTAMP` next to the display text.
struct EventSummary {
    time_micros: Option<i64>,
    row: crate::results::MatchRow,
}

/// One file's place in a scan: the type that decides whether a rule reads
/// it, how many events it holds and one past its highest `record_index`.
struct FileSpan {
    file_id: u32,
    log_type: String,
    rows: u64,
    end: u64,
}

pub struct Store {
    conn: Connection,
    next_match_id: u64,
}

/// Which branches a search needle needs; see `Store::search_filter`.
#[derive(Clone, Copy)]
enum SearchShape {
    None,
    Text,
    TextOrTime,
}

/// A long-lived events appender. One parser file reuses it across every
/// bounded batch, avoiding a DuckDB flush and appender rebuild per 10,000 rows.
pub struct EventWriter<'a> {
    appender: Appender<'a>,
    /// Text bytes handed to the appender since its last flush.
    pending_bytes: usize,
}

/// DuckDB's appender buffers up to 204,800 rows outside the buffer pool
/// (`memory_limit` does not see them) before it commits. Rows with multi-KB
/// JSON bodies times four workers put that in the GBs, so the writer also
/// commits by bytes. 256 MiB: a 478k-row nginx file (3.5 KB rows) peaked at
/// 1.84 GB RSS unbounded, 1.51 GB here, 1.33 GB at 64 MiB — but 64 MiB made
/// every commit smaller than a row group and cost 15% on that file.
const APPENDER_FLUSH_BYTES: usize = 256 << 20;

impl EventWriter<'_> {
    pub fn append(&mut self, events: &[NormalizedEvent]) -> Result<(), StoreError> {
        for event in events {
            if event.record_index > u64::from(u32::MAX) {
                return Err(StoreError::RecordIndexOverflow {
                    file_id: event.file_id,
                });
            }
            let event_id = (u64::from(event.file_id) << 32) | event.record_index;
            self.appender.append_row(params![
                event_id,
                event.file_id,
                event.record_index,
                match event.event_time {
                    Some(t) => Value::Timestamp(
                        TimeUnit::Microsecond,
                        (t.unix_timestamp_nanos() / 1000) as i64,
                    ),
                    None => Value::Null,
                },
                event.event_source,
                event.event_name,
                event.aws_region,
                event.account_id,
                event.source_ip,
                event.user_agent,
                event.identity_type,
                event.identity_arn,
                event.identity_name,
                event.mfa_authenticated,
                event.error_code,
                event.error_message,
                event.read_only,
                event.management_event,
                event.request,
                event.response,
                event.resources,
                event.raw,
            ])?;
            self.pending_bytes += [
                &event.request,
                &event.response,
                &event.resources,
                &event.raw,
            ]
            .iter()
            .map(|text| text.as_ref().map_or(0, String::len))
            .sum::<usize>();
            if self.pending_bytes >= APPENDER_FLUSH_BYTES {
                self.appender.flush()?;
                self.pending_bytes = 0;
            }
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), StoreError> {
        self.appender.flush()?;
        Ok(())
    }
}

impl Store {
    /// Database-wide settings, applied once per open.
    ///
    /// `memory_limit`: the default is 80% of RAM, and the parser's appends
    /// plus the rule pass's per-file scans fill it with cached blocks: a
    /// 31M-row case climbed to many GB of RSS for no speed gain. 1 GiB
    /// measured no slower on a 3M-row subset while RSS fell 3.8 → 2.5 GB
    /// (parse) and 2.2 → 1.3 GB (rule pass). Sorts beyond it spill into the
    /// case's temp directory.
    ///
    /// `checkpoint_threshold`: the 16 MB default made every file's commit
    /// checkpoint, and a checkpoint compresses one row group on one thread
    /// while the other workers wait for the lock (profiled: ~50% of each
    /// worker's time). 512 MB batches several files per checkpoint and stays
    /// inside the buffer pool: 3M-row subset 18.7s → 14.6s, DB size and RSS
    /// unchanged; 1 GB spills and is slower again.
    ///
    /// Extension autoload is off: the JSON extension is linked in, and DuckDB
    /// must never download into `~/.duckdb` from a portable, offline tool
    /// (docs/07).
    fn configure(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(
            "SET memory_limit = '1GiB';
             SET checkpoint_threshold = '512MB';
             SET autoinstall_known_extensions = false;
             SET autoload_known_extensions = false;",
        )?;
        Ok(())
    }

    /// Creates the database and its schema, then records the case row.
    pub fn create(path: &Path, case_id: &str, input_dir: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::configure(&conn)?;
        conn.execute_batch(SCHEMA)?;
        conn.execute(
            "INSERT INTO case_meta (case_id, input_dir, started_at, status, app_version)
             VALUES (?, ?, now(), ?, ?)",
            params![
                case_id,
                input_dir,
                CaseStatus::Running.as_str(),
                env!("CARGO_PKG_VERSION")
            ],
        )?;
        Ok(Self {
            conn,
            next_match_id: 0,
        })
    }

    /// Reopens an existing case, e.g. to view results without re-parsing.
    /// The schema is idempotent and carries column migrations, so an older
    /// case picks them up here. A match table without the summary columns
    /// is rebuilt from its hits, so recorded evaluations survive.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::configure(&conn)?;
        // Detected before the schema runs: `CREATE TABLE IF NOT EXISTS`
        // would keep the old shape, and adding sixteen columns leaves the
        // rows empty either way. The old table is set aside and refilled.
        let old_matches: bool = conn.query_row(
            "SELECT count(*) > 0 FROM information_schema.columns
             WHERE table_name = 'rule_matches'
               AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                               WHERE table_name = 'rule_matches' AND column_name = 'log_type')",
            [],
            |r| r.get(0),
        )?;
        // Schema and refill are one transaction. Were the rename and the new
        // table to persist before the refill, an error or crash midway would
        // leave a new-shaped table with part of the hits, which the next
        // open would accept as complete while the rules still read as
        // evaluated. Rolled back, the next open finds the old table again.
        conn.execute_batch("BEGIN TRANSACTION")?;
        let mut store = Self {
            conn,
            next_match_id: 0,
        };
        if let Err(e) = store.migrate(old_matches) {
            // Best effort: the transaction dies with the connection anyway.
            let _ = store.conn.execute_batch("ROLLBACK");
            return Err(e);
        }
        store.conn.execute_batch("COMMIT")?;
        Ok(store)
    }

    /// The transactional half of [`Self::open`]: applies the schema, sets
    /// the match id counter and, for an old-shaped match table, refills it.
    fn migrate(&mut self, old_matches: bool) -> Result<(), StoreError> {
        if old_matches {
            self.conn.execute_batch(
                "DROP TABLE IF EXISTS rule_matches_v1;
                 ALTER TABLE rule_matches RENAME TO rule_matches_v1;",
            )?;
        }
        self.conn.execute_batch(SCHEMA)?;
        self.next_match_id = self.conn.query_row(
            "SELECT coalesce(max(match_id) + 1, 0) FROM rule_matches",
            [],
            |r| r.get(0),
        )?;
        if old_matches {
            self.migrate_matches()?;
        }
        Ok(())
    }

    /// Refills `rule_matches` from `rule_matches_v1` (id, rule, evidence
    /// only), fetching each hit's summary by event id. Batched so a case
    /// with millions of hits never holds them all at once.
    fn migrate_matches(&mut self) -> Result<(), StoreError> {
        let mut offset = 0u64;
        loop {
            let batch: Vec<(String, crate::rule::Hit)> = {
                let mut stmt = self.conn.prepare(
                    "SELECT rule_id, event_id, matched_fields FROM rule_matches_v1
                     ORDER BY match_id LIMIT ? OFFSET ?",
                )?;
                let rows = stmt.query_map(params![MIGRATION_BATCH, offset], |row| {
                    let fields: String = row.get(2)?;
                    Ok((
                        row.get(0)?,
                        crate::rule::Hit {
                            event_id: row.get(1)?,
                            matched_fields: serde_json::from_str(&fields).unwrap_or_default(),
                        },
                    ))
                })?;
                rows.collect::<Result<_, _>>()?
            };
            if batch.is_empty() {
                break;
            }
            self.append_match_batch(&batch)?;
            offset += batch.len() as u64;
        }
        self.conn.execute_batch("DROP TABLE rule_matches_v1")?;
        Ok(())
    }

    /// Sets the temp directory so large sorts spill inside the case, not into
    /// the system temp dir (docs/07 portability).
    pub fn set_temp_dir(&self, dir: &Path) -> Result<(), StoreError> {
        self.conn.execute_batch(&format!(
            "SET temp_directory = '{}';",
            dir.display().to_string().replace('\'', "''")
        ))?;
        Ok(())
    }

    pub fn register_file(
        &mut self,
        file_id: u32,
        path: &str,
        size_bytes: u64,
        log_type: &str,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO files (file_id, path, size_bytes, log_type, status)
             VALUES (?, ?, ?, ?, 'pending')",
            params![file_id, path, size_bytes, log_type],
        )?;
        Ok(())
    }

    pub fn mark_file(
        &mut self,
        file_id: u32,
        status: &str,
        record_count: Option<u64>,
        note: Option<&str>,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE files SET status = ?, record_count = ?, note = ? WHERE file_id = ?",
            params![status, record_count, note, file_id],
        )?;
        Ok(())
    }

    /// Replaces the recorded payload paths with this run's. One run per
    /// case, so replacing is the same as writing.
    pub fn write_payload_keys<'a>(
        &mut self,
        keys: impl IntoIterator<Item = (&'a str, &'a str, u64)>,
    ) -> Result<(), StoreError> {
        self.conn.execute("DELETE FROM payload_keys", [])?;
        let mut appender = self.conn.appender("payload_keys")?;
        for (log_type, path, events) in keys {
            appender.append_row(params![log_type, path, events])?;
        }
        appender.flush()?;
        Ok(())
    }

    /// Payload paths the case holds, most frequent first within a type;
    /// `log_type` narrows to one type.
    pub fn payload_keys(
        &self,
        log_type: Option<&str>,
    ) -> Result<Vec<crate::results::PayloadKey>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT log_type, path, events FROM payload_keys
             WHERE ? IS NULL OR log_type = ?
             ORDER BY log_type, events DESC, path",
        )?;
        let rows = stmt.query_map(params![log_type, log_type], |row| {
            Ok(crate::results::PayloadKey {
                log_type: row.get(0)?,
                path: row.get(1)?,
                events: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Opens one long-lived appender for a parser file.
    pub fn event_writer(&mut self) -> Result<EventWriter<'_>, StoreError> {
        let appender = self.conn.appender("events")?;
        Ok(EventWriter {
            appender,
            pending_bytes: 0,
        })
    }

    /// Bulk-loads a standalone batch. Parsers should use [`Self::event_writer`]
    /// to reuse one appender across all batches in a file.
    pub fn append_events(&mut self, events: &[NormalizedEvent]) -> Result<(), StoreError> {
        let mut writer = self.event_writer()?;
        writer.append(events)?;
        writer.finish()
    }

    /// Events inside the window's scope (log type and date range).
    pub fn event_count(&self, window: &crate::results::Window) -> Result<u64, StoreError> {
        let sql = format!(
            "SELECT count(*) FROM events e WHERE true {}",
            Self::scope_filter(window, EVENT_TYPE_FILTER)
        );
        Ok(self.conn.query_row(
            &sql,
            duckdb::params_from_iter(Self::scope_params(window)?),
            |r| r.get(0),
        )?)
    }

    /// First and last event day in KST, for the date filter's bounds.
    pub fn day_span(&self) -> Result<(Option<String>, Option<String>), StoreError> {
        Ok(self.conn.query_row(
            "SELECT strftime(min(event_time) + INTERVAL 9 HOUR, '%Y-%m-%d'),
                    strftime(max(event_time) + INTERVAL 9 HOUR, '%Y-%m-%d')
             FROM events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    /// Whether any recorded rule lacks its log type: true for cases written
    /// before the column existed, which the app backfills from the snapshot.
    pub fn rules_lack_log_type(&self) -> Result<bool, StoreError> {
        let missing: u64 = self.conn.query_row(
            "SELECT count(*) FROM rules WHERE log_type IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(missing > 0)
    }

    /// Fills `rules.log_type` from a rule set's `meta: log_type` without
    /// re-evaluating. Only NULL scopes are filled: a scope already restored
    /// from a better source (the case snapshot) must not be overwritten by a
    /// later, less specific one (the bundled rules).
    pub fn backfill_rule_log_types(
        &mut self,
        rules: &[crate::rule::Rule],
    ) -> Result<(), StoreError> {
        for rule in rules {
            if let Some(log_type) = rule.meta.get("log_type") {
                self.conn.execute(
                    "UPDATE rules SET log_type = ? WHERE rule_id = ? AND log_type IS NULL",
                    params![log_type, rule.id],
                )?;
            }
        }
        Ok(())
    }

    /// Whether any recorded rule lacks its display name: true for cases
    /// written before the column existed, which the app backfills.
    pub fn rules_lack_name(&self) -> Result<bool, StoreError> {
        let missing: u64 =
            self.conn
                .query_row("SELECT count(*) FROM rules WHERE name IS NULL", [], |r| {
                    r.get(0)
                })?;
        Ok(missing > 0)
    }

    /// Fills `rules.name` from a rule set's `meta: name`. Only NULLs are
    /// filled and only from rules that declare a name, so a nameless rule
    /// keeps reading as its id instead of pinning the id into the column.
    pub fn backfill_rule_names(&mut self, rules: &[crate::rule::Rule]) -> Result<(), StoreError> {
        for rule in rules {
            if let Some(name) = rule.meta.get("name") {
                self.conn.execute(
                    "UPDATE rules SET name = ? WHERE rule_id = ? AND name IS NULL",
                    params![name, rule.id],
                )?;
            }
        }
        Ok(())
    }

    /// Stored event count per log type, for the type tabs. Grouped by file
    /// id first so the wide join only touches one row per file.
    pub fn log_type_counts(&self) -> Result<Vec<crate::results::LogTypeCount>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT f.log_type, sum(g.n)::UBIGINT
             FROM (SELECT file_id, count(*) AS n FROM events GROUP BY file_id) g
             JOIN files f USING (file_id)
             GROUP BY f.log_type ORDER BY f.log_type",
        )?;
        let mut rows = stmt.query([])?;
        let mut counts = Vec::new();
        while let Some(row) = rows.next()? {
            counts.push(crate::results::LogTypeCount {
                log_type: row.get(0)?,
                events: row.get(1)?,
            });
        }
        Ok(counts)
    }

    pub fn first_event(&self) -> Result<Option<StoredEvent>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, record_index, event_name, identity_arn, mfa_authenticated, raw
             FROM events ORDER BY event_id LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(StoredEvent {
            event_id: row.get(0)?,
            record_index: row.get(1)?,
            event_name: row.get(2)?,
            identity_arn: row.get(3)?,
            mfa_authenticated: row.get(4)?,
            raw: row.get(5)?,
        }))
    }

    /// Every stored event in `event_id` order, for tests and dumps.
    pub fn for_each_event(
        &self,
        mut visit: impl FnMut(u64, NormalizedEvent),
    ) -> Result<(), StoreError> {
        // Files ascend and ids are `file_id << 32 | record_index`, so
        // per-file record order is global id order.
        self.for_each_typed_event(|id, _, event| visit(id, event))
    }

    /// Streams every stored event with its source file's detected log type.
    pub fn for_each_typed_event(
        &self,
        visit: impl FnMut(u64, &str, NormalizedEvent),
    ) -> Result<(), StoreError> {
        self.scan_events(None, |_| true, visit, || false)
    }

    /// Streams stored events for rule evaluation, in `file_id` then
    /// `record_index` order, with each file's detected log type.
    ///
    /// `columns` limits which event columns are read; the rest come back
    /// `None`. A rule only looks at the columns it names, so reading the
    /// JSON bodies for a rule on `event_name` would be pure cost. `None`
    /// reads everything. `wants` skips whole files by log type.
    ///
    /// `cancelled` is polled before the first query, at every file, chunk
    /// and row boundary and once the pass is over, so a run the user
    /// abandoned stops promptly and never reports success. It returns
    /// [`StoreError::Cancelled`]; callers that cannot be cancelled pass
    /// `|| false`.
    pub fn scan_events(
        &self,
        columns: Option<&BTreeSet<&str>>,
        wants: impl FnMut(&str) -> bool,
        visit: impl FnMut(u64, &str, NormalizedEvent),
        cancelled: impl Fn() -> bool,
    ) -> Result<(), StoreError> {
        self.scan_files(columns, None, wants, visit, cancelled)?;
        Ok(())
    }

    /// Streams the events a rule set could match and reports how many the
    /// case holds in total.
    ///
    /// Three narrowings, each leaving the visited events a superset of what
    /// the rules can match: only the columns the rules name are read, files
    /// of a log type no rule applies to are skipped, and — where one can be
    /// derived safely — a necessary condition of the set filters rows inside
    /// DuckDB instead of shipping them into Rust to be rejected there. Rows
    /// that survive are evaluated in full, so hits and evidence are exactly
    /// those of a pass over the whole case.
    ///
    /// The total counts every stored event, skipped and filtered ones
    /// included: a draft count reports its hits as a proportion of the case,
    /// never of the slice the rule narrowed it to.
    pub fn scan_rule_candidates(
        &self,
        rules: &[&crate::rule::Rule],
        visit: impl FnMut(u64, &str, NormalizedEvent),
        cancelled: impl Fn() -> bool,
    ) -> Result<u64, StoreError> {
        let columns: BTreeSet<&str> = rules.iter().copied().flat_map(Rule::columns).collect();
        let candidate = set_candidate(rules);
        self.scan_files(
            Some(&columns),
            candidate.as_ref(),
            |log_type| rules.iter().any(|rule| rule.applies_to(log_type)),
            visit,
            cancelled,
        )
    }

    /// The pass both entry points run; returns the case's stored event count.
    ///
    /// Reads go in bounded chunks, not one query over the table:
    /// `duckdb-rs` materializes a query's whole result, and one holding
    /// every event with its JSON columns reached ~2.5 GB per million rows.
    /// Chunking by `record_index` range inside each file keeps that bound
    /// independent of both the case size and the largest file.
    fn scan_files(
        &self,
        columns: Option<&BTreeSet<&str>>,
        candidate: Option<&Candidate>,
        mut wants: impl FnMut(&str) -> bool,
        mut visit: impl FnMut(u64, &str, NormalizedEvent),
        cancelled: impl Fn() -> bool,
    ) -> Result<u64, StoreError> {
        const CHUNK: u64 = 50_000;
        if cancelled() {
            return Err(StoreError::Cancelled);
        }
        let files = self.file_spans()?;
        let stored = files.iter().map(|file| file.rows).sum();
        // Unselected columns are projected as NULL so row positions stay fixed.
        let projected: Vec<String> = EVENT_COLUMNS
            .iter()
            .map(|name| match columns {
                Some(wanted) if !wanted.contains(name) => format!("NULL AS {name}"),
                _ => (*name).to_owned(),
            })
            .collect();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT event_id, file_id, record_index, {projection}
             FROM events
             WHERE file_id = ? AND record_index >= ? AND record_index < ?{narrowing}
             ORDER BY record_index",
            projection = projected.join(", "),
            narrowing = candidate.map_or("", |candidate| candidate.sql.as_str()),
        ))?;
        // File id and range bounds, then the candidate's values, which are
        // the same for every chunk.
        let mut binds = vec![Value::UInt(0), Value::UBigInt(0), Value::UBigInt(0)];
        binds.extend(candidate.iter().flat_map(|c| c.params.iter().cloned()));
        for file in files {
            if cancelled() {
                return Err(StoreError::Cancelled);
            }
            if !wants(&file.log_type) {
                continue;
            }
            binds[0] = Value::UInt(file.file_id);
            let mut from = 0u64;
            // Bounded by the file's own last record index: how many rows a
            // chunk returned says nothing about whether the file is done.
            // A narrowed chunk holds only candidates, and even an unfiltered
            // one is short wherever a record failed to normalize and left a
            // hole in `record_index`.
            while from < file.end {
                if cancelled() {
                    return Err(StoreError::Cancelled);
                }
                binds[1] = Value::UBigInt(from);
                binds[2] = Value::UBigInt(from + CHUNK);
                let mut rows = stmt.query(duckdb::params_from_iter(binds.iter()))?;
                while let Some(row) = rows.next()? {
                    // Per row, before the columns are read: a chunk holds
                    // 50,000 of them and an abandoned run must stop here,
                    // not at the end of the file.
                    if cancelled() {
                        return Err(StoreError::Cancelled);
                    }
                    let event_id: u64 = row.get(0)?;
                    visit(
                        event_id,
                        &file.log_type,
                        NormalizedEvent {
                            file_id: row.get(1)?,
                            record_index: row.get(2)?,
                            // Time is not needed for rule evaluation yet; skip the parse.
                            event_time: None,
                            event_source: row.get(3)?,
                            event_name: row.get(4)?,
                            aws_region: row.get(5)?,
                            account_id: row.get(6)?,
                            source_ip: row.get(7)?,
                            user_agent: row.get(8)?,
                            identity_type: row.get(9)?,
                            identity_arn: row.get(10)?,
                            identity_name: row.get(11)?,
                            mfa_authenticated: row.get(12)?,
                            error_code: row.get(13)?,
                            error_message: row.get(14)?,
                            read_only: row.get(15)?,
                            management_event: row.get(16)?,
                            request: row.get(17)?,
                            response: row.get(18)?,
                            resources: row.get(19)?,
                            raw: row.get(20)?,
                        },
                    );
                }
                from += CHUNK;
            }
        }
        // A scan that read nothing — no files, or none of the wanted type —
        // must still report a cancel that arrived while it ran.
        if cancelled() {
            return Err(StoreError::Cancelled);
        }
        Ok(stored)
    }

    /// Each file's scan range, read once per pass. The row count and the
    /// last `record_index` are different numbers: the parser numbers every
    /// line of a file and stores only the records that normalized, so the
    /// indexes it wrote have holes. The count is what a case holds; the last
    /// index is how far a scan has to read.
    fn file_spans(&self) -> Result<Vec<FileSpan>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT f.file_id, f.log_type, coalesce(g.rows, 0::UBIGINT), g.last
             FROM files f
             LEFT JOIN (SELECT file_id, count(*)::UBIGINT AS rows, max(record_index) AS last
                        FROM events GROUP BY file_id) g USING (file_id)
             ORDER BY f.file_id",
        )?;
        let rows = stmt.query_map([], |row| {
            let last: Option<u64> = row.get(3)?;
            Ok(FileSpan {
                file_id: row.get(0)?,
                log_type: row.get(1)?,
                rows: row.get(2)?,
                end: last.map_or(0, |last| last + 1),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Drops previous rule hits. Re-evaluating a case must replace results,
    /// not append to them (rules change; events do not).
    /// Starts a rule run: drops previous hits and records the rule metadata
    /// that the results view reads back.
    ///
    /// The two halves are one call on purpose — recording metadata without
    /// clearing duplicates matches, and clearing without recording leaves
    /// severity as `unknown`.
    pub fn begin_rule_run(&mut self, rules: &[crate::rule::Rule]) -> Result<(), StoreError> {
        self.clear_matches()?;
        self.record_rules(rules)
    }

    /// Records the rules used for this evaluation. Keeps the case
    /// self-describing: severity and description survive a directory copy
    /// even without the rule files (docs/07).
    fn record_rules(&mut self, rules: &[crate::rule::Rule]) -> Result<(), StoreError> {
        for rule in rules {
            self.upsert_rule(rule)?;
        }
        Ok(())
    }

    /// Registers or re-registers one rule as not yet evaluated, dropping
    /// any matches it had. Used when a rule is saved: its next selection
    /// evaluates it fresh.
    pub fn reset_rule(&mut self, rule: &crate::rule::Rule) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM rule_matches WHERE rule_id = ?",
            params![rule.id],
        )?;
        self.upsert_rule(rule)
    }

    fn upsert_rule(&mut self, rule: &crate::rule::Rule) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM rules WHERE rule_id = ?", params![rule.id])?;
        self.conn.execute(
            "INSERT INTO rules (rule_id, name, severity, description, log_type, evaluated)
             VALUES (?, ?, ?, ?, ?, false)",
            params![
                rule.id,
                // NULL, not the id: `rule_groups` falls back to the id and
                // a later backfill may still fill it.
                rule.meta.get("name"),
                rule.severity(),
                rule.description(),
                rule.meta.get("log_type")
            ],
        )?;
        Ok(())
    }

    /// Removes a rule and its matches from this case only.
    pub fn remove_rule(&mut self, rule_id: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM rule_matches WHERE rule_id = ?",
            params![rule_id],
        )?;
        self.conn
            .execute("DELETE FROM rules WHERE rule_id = ?", params![rule_id])?;
        Ok(())
    }

    pub fn mark_rule_evaluated(&mut self, rule_id: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE rules SET evaluated = true WHERE rule_id = ?",
            params![rule_id],
        )?;
        Ok(())
    }

    fn clear_matches(&mut self) -> Result<(), StoreError> {
        self.conn.execute("DELETE FROM rule_matches", [])?;
        self.next_match_id = 0;
        Ok(())
    }

    /// A second handle on the **same** database, for writing matches while
    /// streaming events. Opening the file twice would create two independent
    /// databases and the writes would be invisible to the reader. The match
    /// id continues from what is stored, not from this handle's counter:
    /// an earlier handle may have written since.
    pub fn writer_handle(&self) -> Result<Self, StoreError> {
        let conn = self.conn.try_clone()?;
        let next_match_id = conn.query_row(
            "SELECT coalesce(max(match_id) + 1, 0) FROM rule_matches",
            [],
            |r| r.get(0),
        )?;
        Ok(Self {
            conn,
            next_match_id,
        })
    }

    /// Appends one batch of rule hits with each event's summary. Called
    /// repeatedly while streaming so matches never accumulate in memory
    /// (NFR-2). The summary is fetched here rather than carried by the
    /// scan: the scan reads only the columns the rule names, and the hits
    /// are a small fraction of what it reads.
    pub fn append_match_batch(
        &mut self,
        batch: &[(String, crate::rule::Hit)],
    ) -> Result<(), StoreError> {
        let ids: Vec<u64> = batch.iter().map(|(_, hit)| hit.event_id).collect();
        let types = self.file_log_types()?;
        let summaries = self.event_summaries(&ids, &types)?;
        let mut appender = self.conn.appender("rule_matches")?;
        for (rule_id, hit) in batch {
            let fields =
                serde_json::to_string(&hit.matched_fields).unwrap_or_else(|_| "{}".to_string());
            // A hit for an unknown event keeps its evidence; the summary is
            // simply empty. The type comes from the file either way.
            let (time, row) = summaries
                .get(&hit.event_id)
                .map(|s| (s.time_micros, Some(&s.row)))
                .unwrap_or((None, None));
            let text = |pick: fn(&crate::results::MatchRow) -> &Option<String>| {
                row.and_then(|r| pick(r).clone())
            };
            appender.append_row(params![
                self.next_match_id,
                rule_id,
                hit.event_id,
                fields,
                types
                    .get(&((hit.event_id >> 32) as u32))
                    .map(String::as_str)
                    .unwrap_or_default(),
                time.map_or(Value::Null, |us| Value::Timestamp(
                    TimeUnit::Microsecond,
                    us
                )),
                text(|r| &r.event_name),
                text(|r| &r.event_source),
                text(|r| &r.identity_arn),
                text(|r| &r.source_ip),
                text(|r| &r.user_agent),
                text(|r| &r.aws_region),
                text(|r| &r.error_code),
                text(|r| &r.url),
                text(|r| &r.status),
                text(|r| &r.target),
                text(|r| &r.resource),
                text(|r| &r.country),
                text(|r| &r.rule),
                text(|r| &r.method),
            ])?;
            self.next_match_id += 1;
        }
        appender.flush()?;
        Ok(())
    }

    /// Match counts per rule. Severity and description come from the rule
    /// set, so only ids and counts live in the database.
    ///
    /// Only rules that can apply are listed: under a log type, rules scoped
    /// to it or unscoped; otherwise rules for any type the case actually
    /// holds events of. Counts honour the window's type and date range,
    /// read off the match rows themselves.
    pub fn rule_groups(
        &self,
        window: &crate::results::Window,
    ) -> Result<Vec<crate::results::RuleGroup>, StoreError> {
        // Driven from `rules`, not `rule_matches`: a rule that matched
        // nothing is coverage information, and dropping it makes an
        // unexercised rule look like one that was never loaded.
        let sql = format!(
            "SELECT r.rule_id, count(e.event_id), r.severity, r.description, r.evaluated,
                    coalesce(r.name, r.rule_id)
             FROM rules r LEFT JOIN rule_matches e
               ON e.rule_id = r.rule_id {match_scope}
             WHERE r.log_type IS NULL OR {rule_type}
             GROUP BY r.rule_id, r.name, r.severity, r.description, r.evaluated
             ORDER BY count(e.event_id) DESC, r.rule_id",
            match_scope = Self::scope_filter(window, MATCH_TYPE_FILTER),
            rule_type = if window.log_type.is_some() {
                "r.log_type = ?"
            } else {
                "r.log_type IN (SELECT f.log_type FROM files f
                                WHERE EXISTS (SELECT 1 FROM events e WHERE e.file_id = f.file_id))"
            },
        );
        let mut params = Self::scope_params(window)?;
        params.extend(Self::type_params(window.log_type.as_deref()));
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(duckdb::params_from_iter(params))?;
        let mut groups = Vec::new();
        while let Some(row) = rows.next()? {
            groups.push(crate::results::RuleGroup {
                rule_id: row.get(0)?,
                match_count: row.get(1)?,
                severity: row.get(2)?,
                description: row.get(3)?,
                evaluated: row.get(4)?,
                name: row.get(5)?,
            });
        }
        Ok(groups)
    }

    /// Events matched by at least one rule, inside the window's scope.
    pub fn matched_event_count(&self, window: &crate::results::Window) -> Result<u64, StoreError> {
        let sql = format!(
            "SELECT count(DISTINCT e.event_id) FROM rule_matches e WHERE true {}",
            Self::scope_filter(window, MATCH_TYPE_FILTER)
        );
        Ok(self.conn.query_row(
            &sql,
            duckdb::params_from_iter(Self::scope_params(window)?),
            |r| r.get(0),
        )?)
    }

    /// Predicates narrowing rows aliased `e` to the window's log type and
    /// KST date range; `type_filter` is [`EVENT_TYPE_FILTER`] or
    /// [`MATCH_TYPE_FILTER`] depending on the table. Dates are `YYYY-MM-DD`
    /// in KST: `from` is that day's 00:00, `to` runs through the end of that
    /// day. A row without a time is outside any date range. Callers bind
    /// [`Self::scope_params`] before any search params, in this order: log
    /// type, from, to.
    fn scope_filter(window: &crate::results::Window, type_filter: &str) -> String {
        let mut sql = String::new();
        if window.log_type.is_some() {
            sql.push_str(type_filter);
        }
        if window.from.is_some() {
            sql.push_str(" AND e.event_time >= CAST(? AS TIMESTAMP) - INTERVAL 9 HOUR");
        }
        if window.to.is_some() {
            sql.push_str(" AND e.event_time < CAST(? AS TIMESTAMP) - INTERVAL 9 HOUR");
        }
        sql
    }

    fn scope_params(window: &crate::results::Window) -> Result<Vec<Value>, StoreError> {
        let mut params = Self::type_params(window.log_type.as_deref());
        if let Some(from) = &window.from {
            params.push(Value::Text(Self::bound(from, false)?));
        }
        if let Some(to) = &window.to {
            params.push(Value::Text(Self::bound(to, true)?));
        }
        Ok(params)
    }

    /// A KST bound typed by the analyst, as the `YYYY-MM-DD HH:MM:SS` text
    /// the SQL casts. Accepts a day, a minute or a second. `end` turns an
    /// inclusive "until" into the exclusive instant one unit later, so
    /// `2026-06-06` covers the whole day and `2026-06-06 11:00` the minute.
    fn bound(text: &str, end: bool) -> Result<String, StoreError> {
        use time::macros::format_description;
        use time::{Duration, PrimitiveDateTime, Time};

        let bad = || StoreError::BadDateTime(text.to_owned());
        let text = text.trim();
        let (stamp, unit) = match text.len() {
            10 => (
                time::Date::parse(text, format_description!("[year]-[month]-[day]"))
                    .map_err(|_| bad())?
                    .with_time(Time::MIDNIGHT),
                Duration::DAY,
            ),
            16 => (
                PrimitiveDateTime::parse(
                    text,
                    format_description!("[year]-[month]-[day] [hour]:[minute]"),
                )
                .map_err(|_| bad())?,
                Duration::MINUTE,
            ),
            19 => (
                PrimitiveDateTime::parse(
                    text,
                    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"),
                )
                .map_err(|_| bad())?,
                Duration::SECOND,
            ),
            _ => return Err(bad()),
        };
        let stamp = if end {
            stamp.checked_add(unit).ok_or_else(bad)?
        } else {
            stamp
        };
        stamp
            .format(format_description!(
                "[year]-[month]-[day] [hour]:[minute]:[second]"
            ))
            .map_err(|_| bad())
    }

    fn type_params(log_type: Option<&str>) -> Vec<Value> {
        log_type
            .map(|t| Value::Text(t.to_owned()))
            .into_iter()
            .collect()
    }

    /// The search predicate, or nothing when there is no search.
    ///
    /// Each shown column is tested on its own with `ILIKE`, so the scan is a
    /// vectorised substring test per column. The previous form —
    /// `contains(lower(concat_ws(strftime(time), cols...)), lower(?))` —
    /// formatted the time, concatenated and lower-cased five values for
    /// every one of 31M rows before testing anything: 20–40 s per search,
    /// and an empty search paid the same price to match everything.
    ///
    /// The time column is shown in KST, so it is searched as that text; but
    /// `strftime` per row is the single most expensive branch (about 20 s on
    /// 31M rows against 2 s for the four text columns), so it is only added
    /// when the needle reads as a date or clock fragment. A dotted fragment
    /// such as `43.201` is an IP prefix far more often than
    /// `seconds.millis`, and searching it must not cost the time scan.
    /// Callers bind [`Self::search_params`], which mirrors this shape.
    fn search_filter(search: &str) -> &'static str {
        match Self::search_shape(search) {
            SearchShape::None => "",
            SearchShape::Text => {
                "AND (e.event_name ILIKE ? ESCAPE '\\' OR e.event_source ILIKE ? ESCAPE '\\'
                      OR e.identity_arn ILIKE ? ESCAPE '\\' OR e.source_ip ILIKE ? ESCAPE '\\')"
            }
            SearchShape::TextOrTime => {
                "AND (e.event_name ILIKE ? ESCAPE '\\' OR e.event_source ILIKE ? ESCAPE '\\'
                      OR e.identity_arn ILIKE ? ESCAPE '\\' OR e.source_ip ILIKE ? ESCAPE '\\'
                      OR strftime(e.event_time + INTERVAL 9 HOUR, '%Y-%m-%d %H:%M:%S.%g')
                         LIKE ? ESCAPE '\\')"
            }
        }
    }

    fn search_shape(search: &str) -> SearchShape {
        if search.is_empty() {
            return SearchShape::None;
        }
        let timestamp_chars = search
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b':' | b'.' | b' '));
        let dated_or_clocked = search.bytes().any(|b| matches!(b, b'-' | b':'))
            || search.bytes().all(|b| b.is_ascii_digit());
        if timestamp_chars && dated_or_clocked {
            SearchShape::TextOrTime
        } else {
            SearchShape::Text
        }
    }

    /// Parameters for [`Self::search_filter`]: one `%needle%` per branch,
    /// with LIKE metacharacters escaped so the user searches for text, not
    /// patterns.
    fn search_params(search: &str) -> Vec<Value> {
        let branches = match Self::search_shape(search) {
            SearchShape::None => return Vec::new(),
            SearchShape::Text => 4,
            SearchShape::TextOrTime => 5,
        };
        let mut pattern = String::with_capacity(search.len() + 2);
        pattern.push('%');
        for c in search.chars() {
            if matches!(c, '%' | '_' | '\\') {
                pattern.push('\\');
            }
            pattern.push(c);
        }
        pattern.push('%');
        vec![Value::Text(pattern); branches]
    }

    /// `DESC` and `ASC` cannot be bound as parameters, so they are chosen
    /// here from a bool rather than interpolated from anything user-supplied.
    /// `event_id` breaks ties so paging cannot repeat or skip a row when
    /// several events share a timestamp.
    ///
    /// `NULLS LAST` is written out in both directions: DuckDB's default has
    /// moved between versions, and an event whose time failed to parse must
    /// not head the oldest-first list.
    fn order_by(newest_first: bool) -> &'static str {
        if newest_first {
            "ORDER BY e.event_time DESC NULLS LAST, e.event_id DESC"
        } else {
            "ORDER BY e.event_time ASC NULLS LAST, e.event_id ASC"
        }
    }

    fn page_filter(window: &crate::results::Window, params: &mut Vec<Value>) -> String {
        let Some(after) = &window.after else {
            return String::new();
        };
        let comparison = if window.newest_first { "<" } else { ">" };
        if let Some(time) = &after.time_micros {
            params.push(Value::Text(time.clone()));
            params.push(Value::Text(after.event_id.clone()));
            format!(
                "AND ((e.event_time, e.event_id) {comparison}
                      (make_timestamp(CAST(? AS BIGINT)), CAST(? AS UBIGINT))
                      OR e.event_time IS NULL)"
            )
        } else {
            params.push(Value::Text(after.event_id.clone()));
            format!("AND e.event_time IS NULL AND e.event_id {comparison} CAST(? AS UBIGINT)")
        }
    }

    /// One page of every event regardless of rules. This is how an analyst
    /// sees what the rules did not catch.
    ///
    /// Sort only narrow keys, then fetch the page's summaries by primary key.
    /// Continuations seek past the last key instead of sorting discarded rows.
    pub fn all_events(
        &self,
        window: &crate::results::Window,
    ) -> Result<crate::results::EventPage, StoreError> {
        let mut params = Self::scope_params(window)?;
        params.extend(Self::search_params(&window.search));
        let continuation = Self::page_filter(window, &mut params);
        let sql = format!(
            "SELECT e.event_id, epoch_us(e.event_time) FROM events e
             WHERE true {type_filter} {filter} {continuation}
             {order}
             LIMIT ?",
            type_filter = Self::scope_filter(window, EVENT_TYPE_FILTER),
            filter = Self::search_filter(&window.search),
            order = Self::order_by(window.newest_first),
        );
        params.push(Value::UBigInt(window.page_limit()));
        let mut ids = Vec::new();
        let mut last_time: Option<i64> = None;
        {
            let mut stmt = self.conn.prepare(&sql)?;
            let mut rows = stmt.query(duckdb::params_from_iter(params))?;
            while let Some(row) = rows.next()? {
                ids.push(row.get::<_, u64>(0)?);
                last_time = row.get(1)?;
            }
        }
        let next_cursor = ids.last().map(|id| crate::results::EventCursor {
            event_id: id.to_string(),
            time_micros: last_time.map(|us| us.to_string()),
        });
        let mut summaries = self.event_summaries(&ids, &self.file_log_types()?)?;
        // Back in sort order: the lookup returns them keyed, not ordered.
        let rows = ids
            .iter()
            .filter_map(|id| summaries.remove(id))
            .map(|s| s.row)
            .collect();
        Ok(crate::results::EventPage {
            rows,
            next_cursor,
            total: None,
        })
    }

    /// Summaries of the given events, by id. Lists of constants go through
    /// the primary key index, so this costs the same on a 300M-row case as
    /// on a small one. Ids the case does not hold are absent from the map.
    ///
    /// A rule that hits most of a case asks for long runs of consecutive
    /// ids instead. Those are read as one range: a batch of 10,000 hits is
    /// ten inlined 1,000-constant `IN` lists to parse and 10,000 index
    /// probes, against a single scan of the rows they sit in.
    fn event_summaries(
        &self,
        ids: &[u64],
        types: &HashMap<u32, String>,
    ) -> Result<HashMap<u64, EventSummary>, StoreError> {
        let mut out = HashMap::with_capacity(ids.len());
        if let Some((first, last)) = dense_range(ids) {
            let wanted: std::collections::HashSet<u64> = ids.iter().copied().collect();
            let mut stmt = self.conn.prepare(&format!(
                "SELECT {EVENT_SUMMARY_COLUMNS} FROM events e
                 WHERE e.event_id >= ? AND e.event_id <= ?"
            ))?;
            let mut rows = stmt.query(params![first, last])?;
            while let Some(row) = rows.next()? {
                // The gaps inside the range are read but not built: only the
                // ids that were asked for become summaries.
                if wanted.contains(&row.get::<_, u64>(0)?) {
                    let summary = Self::read_summary(row, types, "{}".to_owned())?;
                    out.insert(summary.row.event_id, summary);
                }
            }
            return Ok(out);
        }
        for chunk in ids.chunks(SUMMARY_LOOKUP_BATCH) {
            // Ids are integers we computed, never user text: safe to inline,
            // and a bound list would not reach the index.
            let list = chunk
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let mut stmt = self.conn.prepare(&format!(
                "SELECT {EVENT_SUMMARY_COLUMNS} FROM events e WHERE e.event_id IN ({list})"
            ))?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let summary = Self::read_summary(row, types, "{}".to_owned())?;
                out.insert(summary.row.event_id, summary);
            }
        }
        Ok(out)
    }

    /// Reads one row shaped by [`EVENT_SUMMARY_COLUMNS`] or
    /// [`MATCH_SUMMARY_COLUMNS`]. Ids are `file_id << 32 | record_index`,
    /// so the type comes from the small files table rather than a join.
    fn read_summary(
        row: &duckdb::Row<'_>,
        types: &HashMap<u32, String>,
        matched_fields: String,
    ) -> Result<EventSummary, StoreError> {
        let event_id: u64 = row.get(0)?;
        Ok(EventSummary {
            time_micros: row.get(1)?,
            row: crate::results::MatchRow {
                event_id,
                event_time: row.get(2)?,
                event_name: row.get(3)?,
                event_source: row.get(4)?,
                identity_arn: row.get(5)?,
                source_ip: row.get(6)?,
                url: row.get(7)?,
                status: row.get(8)?,
                target: row.get(9)?,
                user_agent: row.get(10)?,
                aws_region: row.get(11)?,
                error_code: row.get(12)?,
                resource: row.get(13)?,
                country: row.get(14)?,
                rule: row.get(15)?,
                method: row.get(16)?,
                matched_fields,
                log_type: types
                    .get(&((event_id >> 32) as u32))
                    .cloned()
                    .unwrap_or_default(),
            },
        })
    }

    fn file_log_types(&self) -> Result<HashMap<u32, String>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT file_id, log_type FROM files")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Events matching the window's type and search, for the all-events
    /// view's total.
    pub fn event_count_matching(&self, window: &crate::results::Window) -> Result<u64, StoreError> {
        let sql = format!(
            "SELECT count(*) FROM events e WHERE true {} {}",
            Self::scope_filter(window, EVENT_TYPE_FILTER),
            Self::search_filter(&window.search)
        );
        let mut params = Self::scope_params(window)?;
        params.extend(Self::search_params(&window.search));
        Ok(self
            .conn
            .query_row(&sql, duckdb::params_from_iter(params), |r| r.get(0))?)
    }

    /// One event's stored columns, keyed by `mapping::Field` names.
    ///
    /// The detail view reads this rather than re-resolving the raw record:
    /// the row is what the rules were evaluated against, and the mapping in
    /// the UI belongs to the next parse, not this case.
    pub fn event_fields(&self, event_id: u64) -> Result<Vec<(String, Option<String>)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT strftime(event_time + INTERVAL 9 HOUR, '%Y-%m-%d %H:%M:%S.%g'),
                    event_source, event_name, aws_region, account_id, source_ip,
                    user_agent, identity_type, identity_arn, identity_name,
                    CAST(mfa_authenticated AS VARCHAR), error_code, error_message,
                    CAST(read_only AS VARCHAR), CAST(management_event AS VARCHAR),
                    request, response, resources
             FROM events WHERE event_id = ?",
        )?;
        let mut rows = stmt.query(params![event_id])?;
        let Some(row) = rows.next()? else {
            return Ok(Vec::new());
        };
        // Same order as `Field::ALL` minus its own ordering concerns: the
        // caller maps positions onto field keys.
        const KEYS: [&str; 18] = [
            "event_time",
            "event_source",
            "event_name",
            "aws_region",
            "account_id",
            "source_ip",
            "user_agent",
            "identity_type",
            "identity_arn",
            "identity_name",
            "mfa_authenticated",
            "error_code",
            "error_message",
            "read_only",
            "management_event",
            "request",
            "response",
            "resources",
        ];
        let mut fields = Vec::with_capacity(KEYS.len());
        for (index, key) in KEYS.iter().enumerate() {
            fields.push(((*key).to_owned(), row.get::<_, Option<String>>(index)?));
        }
        Ok(fields)
    }

    /// One page of a rule's matches, from the match table alone: the
    /// summary was stored with the hit, so no event is read. The search is
    /// scoped to this rule: it narrows what the rule already selected
    /// rather than searching the whole case.
    pub fn rule_matches(
        &self,
        rule_id: &str,
        window: &crate::results::Window,
    ) -> Result<crate::results::EventPage, StoreError> {
        let mut params = vec![Value::Text(rule_id.to_owned())];
        params.extend(Self::scope_params(window)?);
        params.extend(Self::search_params(&window.search));
        let continuation = Self::page_filter(window, &mut params);
        let sql = format!(
            "SELECT {MATCH_SUMMARY_COLUMNS}, e.matched_fields FROM rule_matches e
             WHERE e.rule_id = ? {type_filter} {filter} {continuation}
             {order}
             LIMIT ?",
            type_filter = Self::scope_filter(window, MATCH_TYPE_FILTER),
            filter = Self::search_filter(&window.search),
            order = Self::order_by(window.newest_first),
        );
        params.push(Value::UBigInt(window.page_limit()));
        let types = self.file_log_types()?;
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(duckdb::params_from_iter(params))?;
        let mut out = Vec::new();
        let mut last_time = None;
        while let Some(row) = rows.next()? {
            let summary = Self::read_summary(row, &types, row.get(17)?)?;
            last_time = summary.time_micros;
            out.push(summary.row);
        }
        let next_cursor = out.last().map(|row| crate::results::EventCursor {
            event_id: row.event_id.to_string(),
            time_micros: last_time.map(|us| us.to_string()),
        });
        Ok(crate::results::EventPage {
            rows: out,
            next_cursor,
            total: None,
        })
    }

    /// A rule's matches under the window's type, range and search, for the
    /// count under the table. Without any of them this is the group's hit
    /// count.
    pub fn rule_match_count(
        &self,
        rule_id: &str,
        window: &crate::results::Window,
    ) -> Result<u64, StoreError> {
        let sql = format!(
            "SELECT count(*) FROM rule_matches e WHERE e.rule_id = ? {} {}",
            Self::scope_filter(window, MATCH_TYPE_FILTER),
            Self::search_filter(&window.search)
        );
        let mut params = vec![Value::Text(rule_id.to_owned())];
        params.extend(Self::scope_params(window)?);
        params.extend(Self::search_params(&window.search));
        Ok(self
            .conn
            .query_row(&sql, duckdb::params_from_iter(params), |r| r.get(0))?)
    }

    /// The original record for one event, or `None` if it was not kept.
    pub fn raw_record(&self, event_id: u64) -> Result<Option<String>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT raw FROM events WHERE event_id = ?")?;
        let mut rows = stmt.query(params![event_id])?;
        match rows.next()? {
            Some(row) => Ok(row.get(0)?),
            None => Ok(None),
        }
    }

    pub fn match_count(&self) -> Result<u64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT count(*) FROM rule_matches", [], |r| r.get(0))?)
    }

    pub fn finish(&self, status: CaseStatus) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE case_meta SET status = ?, finished_at = now()",
            params![status.as_str()],
        )?;
        Ok(())
    }

    pub fn case_status(&self) -> Result<CaseStatus, StoreError> {
        let value: String = self
            .conn
            .query_row("SELECT status FROM case_meta", [], |r| r.get(0))?;
        Ok(CaseStatus::parse(&value))
    }

    pub fn finished_at(&self) -> Result<Option<OffsetDateTime>, StoreError> {
        let micros: Option<i64> =
            self.conn
                .query_row("SELECT epoch_us(finished_at) FROM case_meta", [], |r| {
                    r.get(0)
                })?;
        Ok(micros.and_then(|us| OffsetDateTime::from_unix_timestamp_nanos(us as i128 * 1000).ok()))
    }

    /// Writes `case.json`, the derived copy used to list cases without
    /// opening every database. `case_meta` stays the source of truth (docs/07).
    pub fn write_case_json(&self, case_dir: &Path) -> Result<(), StoreError> {
        let meta = self.case_meta()?;
        let json = serde_json::json!({
            "case_id": meta.case_id,
            "input_dir": meta.input_dir,
            "status": meta.status.as_str(),
            "app_version": meta.app_version,
            "event_count": self.event_count(&Default::default())?,
        });
        std::fs::write(
            case_dir.join("case.json"),
            serde_json::to_vec_pretty(&json).map_err(StoreError::CaseJson)?,
        )
        .map_err(|e| StoreError::CaseJson(serde_json::Error::io(e)))?;
        Ok(())
    }

    pub fn case_meta(&self) -> Result<CaseMeta, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT case_id, input_dir, status, app_version FROM case_meta")?;
        let mut rows = stmt.query([])?;
        let row = rows
            .next()?
            .ok_or_else(|| StoreError::MissingMeta("case_meta".into()))?;
        let status: String = row.get(2)?;
        Ok(CaseMeta {
            case_id: row.get(0)?,
            input_dir: row.get(1)?,
            status: CaseStatus::parse(&status),
            app_version: row.get(3)?,
        })
    }
}

/// The id range to read in one scan, for a batch long enough to be worth it
/// and packed tightly enough that reading the gaps costs less than probing
/// the index per id. Ids are `file_id << 32 | record_index`, so a batch
/// spanning two files spans billions and falls back to the id lists.
fn dense_range(ids: &[u64]) -> Option<(u64, u64)> {
    if ids.len() < SUMMARY_LOOKUP_BATCH {
        return None;
    }
    let first = *ids.iter().min()?;
    let last = *ids.iter().max()?;
    (last - first < 2 * ids.len() as u64).then_some((first, last))
}

/// Columns a candidate filter may test. Each is a `VARCHAR` the evaluator
/// reads back as a plain string, so SQL equality and the evaluator's are
/// the same relation, byte for byte. JSON bodies, booleans and timestamps
/// are left out: there the two disagree (rendered numbers, string
/// booleans, formatted times), and a filter that drops one row the rule
/// would have matched is a wrong answer, not a slow one.
const FILTERABLE_COLUMNS: [&str; 11] = [
    "event_source",
    "event_name",
    "aws_region",
    "account_id",
    "source_ip",
    "user_agent",
    "identity_type",
    "identity_arn",
    "identity_name",
    "error_code",
    "error_message",
];

/// A necessary condition for a rule set: every event the set can match
/// satisfies it, so the scan may skip the rest. The converse does not
/// hold, which is why rows that pass are still evaluated in full.
struct Candidate {
    /// Ready to append to the scan's `WHERE`, leading ` AND` included.
    sql: String,
    params: Vec<Value>,
}

/// The filter for a whole set. An event matches the set when it matches one
/// of its rules, so the rules' filters are OR-ed — and a single rule that
/// yields none leaves the whole set unfiltered, since anything narrower
/// would drop that rule's hits.
fn set_candidate(rules: &[&Rule]) -> Option<Candidate> {
    let mut sql = String::new();
    let mut params = Vec::new();
    for rule in rules {
        let candidate = rule_candidate(rule)?;
        if !sql.is_empty() {
            sql.push_str(" OR ");
        }
        sql.push_str(&candidate.sql);
        params.extend(candidate.params);
    }
    (!sql.is_empty()).then(|| Candidate {
        sql: format!(" AND ({sql})"),
        params,
    })
}

/// One rule's filter, built from the field conditions its condition cannot
/// hold without. A rule whose required conditions are all unsupported —
/// regexes, negations, JSON paths — gets none.
fn rule_candidate(rule: &Rule) -> Option<Candidate> {
    let required = necessary_vars(&rule.condition);
    let mut sql = String::new();
    let mut params = Vec::new();
    for field in &rule.fields {
        // A variable declared twice is satisfied by either condition, so
        // neither of them is required on its own.
        let alone = rule.fields.iter().filter(|f| f.var == field.var).count() == 1;
        if !alone || !required.contains(field.var.as_str()) {
            continue;
        }
        let Some((predicate, values)) = column_predicate(field) else {
            continue;
        };
        if !sql.is_empty() {
            sql.push_str(" AND ");
        }
        sql.push_str(&predicate);
        params.extend(values);
    }
    (!sql.is_empty()).then(|| Candidate {
        sql: format!("({sql})"),
        params,
    })
}

/// The variables a condition cannot hold without. Conservative by
/// construction: a form that does not require a variable contributes none,
/// so the filter derived from these can only ever be weaker than the rule.
fn necessary_vars(condition: &Condition) -> BTreeSet<&str> {
    match condition {
        Condition::Var(var) => BTreeSet::from([var.as_str()]),
        Condition::And(a, b) => {
            let mut vars = necessary_vars(a);
            vars.extend(necessary_vars(b));
            vars
        }
        // Either side may be the one that held, so only what both require.
        Condition::Or(a, b) => necessary_vars(a)
            .intersection(&necessary_vars(b))
            .copied()
            .collect(),
        // A variable that must *not* hold says nothing about the rows that
        // do match, and neither does anything under the negation.
        Condition::Not(_) => BTreeSet::new(),
        // `N of (...)` pins a particular variable only when it needs them all.
        Condition::NOf(count, vars) if *count >= vars.len() => {
            vars.iter().map(String::as_str).collect()
        }
        Condition::NOf(..) => BTreeSet::new(),
    }
}

/// One field condition as SQL, where the database and the evaluator decide
/// it the same way: `==` and `in` over a stored text column. Case-folding,
/// substrings, regexes, numeric order, `exists`/`missing` and dotted JSON
/// paths are left to the evaluator.
fn column_predicate(field: &FieldCondition) -> Option<(String, Vec<Value>)> {
    let column = FILTERABLE_COLUMNS
        .iter()
        .find(|name| **name == field.field)?;
    match (field.op, &field.value) {
        (Op::Eq, Literal::Str(text)) => {
            Some((format!("{column} = ?"), vec![Value::Text(text.clone())]))
        }
        // An empty set matches nothing; `IN ()` is not SQL, so leave it.
        (Op::In, Literal::Set(items)) if !items.is_empty() => Some((
            format!("{column} IN ({})", vec!["?"; items.len()].join(", ")),
            items.iter().cloned().map(Value::Text).collect(),
        )),
        _ => None,
    }
}
