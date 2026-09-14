//! DuckDB session store. One case = one database file
//! (docs/05-data-model.md).

use std::collections::BTreeSet;
use std::path::Path;

use duckdb::types::{TimeUnit, Value};
use duckdb::{params, Appender, Connection};
use time::OffsetDateTime;

use crate::model::NormalizedEvent;

const SCHEMA: &str = include_str!("store/schema.sql");

/// The summary columns a match row carries, read off the paged subquery
/// alias `e`. HTTP-style fields (ALB, WAF, API Gateway, nginx) come out of
/// the JSON bodies; CloudTrail rows get NULLs there.
const MATCH_ROW_COLUMNS: &str = "e.event_id,
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
    /// case picks them up here.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::configure(&conn)?;
        conn.execute_batch(SCHEMA)?;
        let next_match: u64 = conn
            .query_row(
                "SELECT coalesce(max(match_id) + 1, 0) FROM rule_matches",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        Ok(Self {
            conn,
            next_match_id: next_match,
        })
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
            Self::scope_filter(window)
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
        self.scan_events(None, |_| true, visit)
    }

    /// Streams stored events for rule evaluation, in `file_id` then
    /// `record_index` order, with each file's detected log type.
    ///
    /// `columns` limits which event columns are read; the rest come back
    /// `None`. A rule only looks at the columns it names, so reading the
    /// JSON bodies for a rule on `event_name` would be pure cost. `None`
    /// reads everything. `wants` skips whole files by log type.
    ///
    /// Reads go in bounded chunks, not one query over the table:
    /// `duckdb-rs` materializes a query's whole result, and one holding
    /// every event with its JSON columns reached ~2.5 GB per million rows.
    /// Chunking by `record_index` range inside each file keeps that bound
    /// independent of both the case size and the largest file.
    pub fn scan_events(
        &self,
        columns: Option<&BTreeSet<&str>>,
        mut wants: impl FnMut(&str) -> bool,
        mut visit: impl FnMut(u64, &str, NormalizedEvent),
    ) -> Result<(), StoreError> {
        const CHUNK: u64 = 50_000;
        let files: Vec<(u32, String)> = {
            let mut stmt = self
                .conn
                .prepare("SELECT file_id, log_type FROM files ORDER BY file_id")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        // Unselected columns are projected as NULL so row positions stay fixed.
        let projected: Vec<String> = EVENT_COLUMNS
            .iter()
            .map(|name| match columns {
                Some(wanted) if !wanted.contains(name) => format!("NULL AS {name}"),
                _ => (*name).to_owned(),
            })
            .collect();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT event_id, file_id, record_index, {}
             FROM events
             WHERE file_id = ? AND record_index >= ? AND record_index < ?
             ORDER BY record_index",
            projected.join(", ")
        ))?;
        for (file_id, log_type) in files {
            if !wants(&log_type) {
                continue;
            }
            let mut from = 0u64;
            loop {
                let mut rows = stmt.query(params![file_id, from, from + CHUNK])?;
                let mut seen = 0u64;
                while let Some(row) = rows.next()? {
                    seen += 1;
                    let event_id: u64 = row.get(0)?;
                    visit(
                        event_id,
                        &log_type,
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
                // Record indexes are dense per file, so a short chunk is the
                // last one.
                if seen < CHUNK {
                    break;
                }
                from += CHUNK;
            }
        }
        Ok(())
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
        self.conn.execute("DELETE FROM rules", [])?;
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
            "INSERT INTO rules (rule_id, severity, description, log_type, evaluated)
             VALUES (?, ?, ?, ?, false)",
            params![
                rule.id,
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

    /// Appends one batch of rule hits. Called repeatedly while streaming so
    /// matches never accumulate in memory (NFR-2).
    pub fn append_match_batch(
        &mut self,
        batch: &[(String, crate::rule::Hit)],
    ) -> Result<(), StoreError> {
        let mut appender = self.conn.appender("rule_matches")?;
        for (rule_id, hit) in batch {
            let fields =
                serde_json::to_string(&hit.matched_fields).unwrap_or_else(|_| "{}".to_string());
            appender.append_row(params![self.next_match_id, rule_id, hit.event_id, fields])?;
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
    /// holds events of. Counts honour the window's date range.
    pub fn rule_groups(
        &self,
        window: &crate::results::Window,
    ) -> Result<Vec<crate::results::RuleGroup>, StoreError> {
        // Driven from `rules`, not `rule_matches`: a rule that matched
        // nothing is coverage information, and dropping it makes an
        // unexercised rule look like one that was never loaded.
        let sql = format!(
            "SELECT r.rule_id, count(m.event_id), r.severity, r.description, r.evaluated
             FROM rules r LEFT JOIN rule_matches m
               ON m.rule_id = r.rule_id {match_scope}
             WHERE r.log_type IS NULL OR {rule_type}
             GROUP BY r.rule_id, r.severity, r.description, r.evaluated
             ORDER BY count(m.event_id) DESC, r.rule_id",
            match_scope = Self::match_scope(window),
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
            });
        }
        Ok(groups)
    }

    /// Events matched by at least one rule, inside the window's scope.
    pub fn matched_event_count(&self, window: &crate::results::Window) -> Result<u64, StoreError> {
        let sql = format!(
            "SELECT count(DISTINCT event_id) FROM rule_matches m WHERE true {}",
            Self::match_scope(window)
        );
        Ok(self.conn.query_row(
            &sql,
            duckdb::params_from_iter(Self::scope_params(window)?),
            |r| r.get(0),
        )?)
    }

    /// Predicates narrowing events `e` to the window's log type and KST date
    /// range. Dates are `YYYY-MM-DD` in KST: `from` is that day's 00:00, `to`
    /// runs through the end of that day. An event without a time is outside
    /// any date range. Callers bind [`Self::scope_params`] before any search
    /// params, in this order: log type, from, to.
    fn scope_filter(window: &crate::results::Window) -> String {
        let mut sql = Self::type_filter(window.log_type.as_deref(), "e.file_id");
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

    /// The same scope for a `rule_matches m` row, through its event. Empty
    /// when the window is unscoped so the common case stays a plain scan.
    fn match_scope(window: &crate::results::Window) -> String {
        if window.log_type.is_none() && window.from.is_none() && window.to.is_none() {
            return String::new();
        }
        format!(
            "AND m.event_id IN (SELECT e.event_id FROM events e WHERE true {})",
            Self::scope_filter(window)
        )
    }

    /// Restricts rows to one log type through the file they came from.
    fn type_filter(log_type: Option<&str>, file_expr: &str) -> String {
        match log_type {
            None => String::new(),
            Some(_) => format!("AND {file_expr} IN (SELECT file_id FROM files WHERE log_type = ?)"),
        }
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

    /// One page of every event regardless of rules. This is how an analyst
    /// sees what the rules did not catch.
    pub fn all_events(
        &self,
        window: &crate::results::Window,
    ) -> Result<Vec<crate::results::MatchRow>, StoreError> {
        // JSON extraction sits outside the paged subquery so it runs on the
        // page's rows only, never on every row the sort considered.
        let sql = format!(
            "SELECT {cols}, '{{}}' FROM (
                SELECT e.* FROM events e
                WHERE true {type_filter} {filter}
                {order}
                LIMIT ? OFFSET ?) e",
            cols = MATCH_ROW_COLUMNS,
            type_filter = Self::scope_filter(window),
            filter = Self::search_filter(&window.search),
            order = Self::order_by(window.newest_first),
        );
        let mut params = Self::scope_params(window)?;
        params.extend(Self::search_params(&window.search));
        params.push(Value::UBigInt(window.page_limit()));
        params.push(Value::UBigInt(window.offset));
        self.match_rows(&sql, params)
    }

    /// Runs a paged query shaped by [`MATCH_ROW_COLUMNS`] plus a trailing
    /// `matched_fields` column and resolves each row's log type.
    fn match_rows(
        &self,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<Vec<crate::results::MatchRow>, StoreError> {
        let types = self.file_log_types()?;
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query(duckdb::params_from_iter(params))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let event_id: u64 = row.get(0)?;
            out.push(crate::results::MatchRow {
                event_id,
                event_time: row.get(1)?,
                event_name: row.get(2)?,
                event_source: row.get(3)?,
                identity_arn: row.get(4)?,
                source_ip: row.get(5)?,
                url: row.get(6)?,
                status: row.get(7)?,
                target: row.get(8)?,
                user_agent: row.get(9)?,
                aws_region: row.get(10)?,
                error_code: row.get(11)?,
                resource: row.get(12)?,
                country: row.get(13)?,
                rule: row.get(14)?,
                method: row.get(15)?,
                matched_fields: row.get(16)?,
                // Ids are `file_id << 32 | record_index`; the small files
                // table is read once instead of joined under the sort.
                log_type: types
                    .get(&((event_id >> 32) as u32))
                    .cloned()
                    .unwrap_or_default(),
            });
        }
        Ok(out)
    }

    fn file_log_types(&self) -> Result<std::collections::HashMap<u32, String>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT file_id, log_type FROM files")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Events matching the window's type and search, for the all-events
    /// view's total.
    pub fn event_count_matching(&self, window: &crate::results::Window) -> Result<u64, StoreError> {
        let sql = format!(
            "SELECT count(*) FROM events e WHERE true {} {}",
            Self::scope_filter(window),
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

    /// One page of a rule's matches, joined to the event summary. The search
    /// is scoped to this rule: it narrows what the rule already selected
    /// rather than searching the whole case.
    pub fn rule_matches(
        &self,
        rule_id: &str,
        window: &crate::results::Window,
    ) -> Result<Vec<crate::results::MatchRow>, StoreError> {
        let sql = format!(
            "SELECT {cols}, e.matched_fields FROM (
                SELECT e.*, m.matched_fields
                FROM rule_matches m JOIN events e USING (event_id)
                WHERE m.rule_id = ? {type_filter} {filter}
                {order}
                LIMIT ? OFFSET ?) e",
            cols = MATCH_ROW_COLUMNS,
            type_filter = Self::scope_filter(window),
            filter = Self::search_filter(&window.search),
            order = Self::order_by(window.newest_first),
        );
        let mut params = vec![Value::Text(rule_id.to_owned())];
        params.extend(Self::scope_params(window)?);
        params.extend(Self::search_params(&window.search));
        params.push(Value::UBigInt(window.page_limit()));
        params.push(Value::UBigInt(window.offset));
        self.match_rows(&sql, params)
    }

    /// A rule's matches under the window's type and search, for the count
    /// under the table. Without either this is the group's hit count.
    pub fn rule_match_count(
        &self,
        rule_id: &str,
        window: &crate::results::Window,
    ) -> Result<u64, StoreError> {
        let sql = format!(
            "SELECT count(*) FROM rule_matches m JOIN events e USING (event_id)
             WHERE m.rule_id = ? {} {}",
            Self::scope_filter(window),
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
