//! Results view queries. Aggregation runs in DuckDB so the UI never loads a
//! whole case into memory (FR-6, NFR-2).

use serde::{Deserialize, Serialize};
use specta::Type;

use crate::store::{Store, StoreError};

/// One page of rows: which slice, filtered how, ordered how. Crosses IPC as
/// one object so the commands do not grow a parameter per filter.
#[derive(Debug, Clone, Default, Deserialize, Type)]
pub struct Window {
    /// Continue after the previous page; reset when filters or order change.
    pub after: Option<EventCursor>,
    #[specta(type = u32)]
    pub limit: u64,
    /// Case-insensitive substring over the columns the table shows. Empty
    /// matches everything. Searching hidden columns would return rows whose
    /// reason for matching is invisible.
    pub search: String,
    /// Oldest first by default: an incident is read forwards in time.
    pub newest_first: bool,
    /// Restrict to events from files of this `files.log_type`; `None` is
    /// every type. Drives the type tabs.
    pub log_type: Option<String>,
    /// Inclusive KST day bounds, `YYYY-MM-DD`. Applied above every other
    /// filter: rule counts, event list and matches all honour them.
    pub from: Option<String>,
    pub to: Option<String>,
}

impl Window {
    /// The page size actually used. Clamped at the one place the queries bind
    /// it: a zero from the UI would return an empty page forever, and an
    /// unbounded limit would put the whole case in one IPC payload (NFR-2).
    pub fn page_limit(&self) -> u64 {
        self.limit.clamp(1, 1_000)
    }
}

/// Exact sort key, separate from the millisecond KST display value.
/// Strings preserve the full database precision across JavaScript IPC.
#[derive(Debug, Clone, Deserialize, Serialize, Type)]
pub struct EventCursor {
    pub event_id: String,
    pub time_micros: Option<String>,
}

#[derive(Debug, Clone, Serialize, Type)]
pub struct RuleGroup {
    pub rule_id: String,
    /// `meta: name`, or the id when the rule has none.
    pub name: String,
    pub severity: String,
    pub description: String,
    #[specta(type = u32)]
    pub match_count: u64,
    /// False until the rule has been run over this case; `match_count` is
    /// meaningless before that.
    pub evaluated: bool,
}

/// One matched event, summarized. The raw record is fetched separately.
#[derive(Debug, Clone, Serialize, Type)]
pub struct MatchRow {
    #[specta(type = f64)]
    pub event_id: u64,
    pub event_time: Option<String>,
    pub event_name: Option<String>,
    pub event_source: Option<String>,
    pub identity_arn: Option<String>,
    pub source_ip: Option<String>,
    /// `files.log_type` of the event's source file; picks the column set.
    pub log_type: String,
    pub user_agent: Option<String>,
    pub aws_region: Option<String>,
    pub error_code: Option<String>,
    /// CloudTrail only: ARN of the first entry in `resources`.
    pub resource: Option<String>,
    /// ALB only: `request.url`, `response.elb_status_code`, `resources.target`.
    pub url: Option<String>,
    pub status: Option<String>,
    pub target: Option<String>,
    /// WAF only: request origin country and the rule that decided the action.
    pub country: Option<String>,
    pub rule: Option<String>,
    /// HTTP method from the request body; `event_name` already carries it
    /// for HTTP producers, but WAF puts the action there instead.
    pub method: Option<String>,
    /// JSON object of `$var` to the value that satisfied it (docs/04).
    pub matched_fields: String,
}

/// Parsed events per log type, for the type tabs.
#[derive(Debug, Clone, Serialize, Type)]
pub struct LogTypeCount {
    pub log_type: String,
    #[specta(type = u32)]
    pub events: u64,
}

/// The results sidebar: type tabs, date bounds, rule groups and the case
/// totals under the window's scope. Rows are paged separately
/// ([`rule_matches`], [`all_events`]) so scrolling never recomputes these.
#[derive(Debug, Clone, Serialize, Type, Default)]
pub struct ResultPage {
    /// Every type in the case, unaffected by the window's type filter so the
    /// tabs stay stable while one is selected.
    pub log_types: Vec<LogTypeCount>,
    /// First and last event day in KST across the whole case; bounds for
    /// the date filter. `None` when the case has no timed event.
    pub first_day: Option<String>,
    pub last_day: Option<String>,
    pub groups: Vec<RuleGroup>,
    #[specta(type = u32)]
    pub total_events: u64,
    #[specta(type = u32)]
    pub matched_events: u64,
    /// Events no rule matched. Shown so a coverage gap is visible, not hidden.
    #[specta(type = u32)]
    pub unmatched_events: u64,
}

/// Lists the rule groups and totals of a parsed case.
///
/// Everything comes from the case database, including rule metadata, so a
/// copied case renders identically without its rule files. The window's
/// search is ignored: the sidebar describes the rules, not a filtered list.
pub fn query(store: &Store, window: &Window) -> Result<ResultPage, StoreError> {
    let (first_day, last_day) = store.day_span()?;
    let total_events = store.event_count(window)?;
    let matched_events = store.matched_event_count(window)?;
    Ok(ResultPage {
        log_types: store.log_type_counts()?,
        first_day,
        last_day,
        groups: store.rule_groups(window)?,
        total_events,
        matched_events,
        unmatched_events: total_events.saturating_sub(matched_events),
    })
}

/// One page of rows, with the total that page was drawn from.
#[derive(Debug, Clone, Serialize, Type, Default)]
pub struct EventPage {
    pub rows: Vec<MatchRow>,
    /// Exact filtered count on the first page; continuations do not recount.
    #[specta(type = Option<f64>)]
    pub total: Option<u64>,
    /// Last returned sort key, or `None` when this page is empty.
    pub next_cursor: Option<EventCursor>,
}

/// Pages one rule's matches. The total is the filtered count: the number
/// under the table describes the list the analyst is looking at, while the
/// sidebar group keeps the rule's real hit count.
pub fn rule_matches(
    store: &Store,
    rule_id: &str,
    window: &Window,
) -> Result<EventPage, StoreError> {
    let mut page = store.rule_matches(rule_id, window)?;
    if window.after.is_none() {
        page.total = Some(store.rule_match_count(rule_id, window)?);
    }
    Ok(page)
}

/// One JSON path seen inside a payload column while parsing, and how many
/// events of that log type carried it (docs/04 "페이로드 키").
#[derive(Debug, Clone, Serialize, Type)]
pub struct PayloadKey {
    pub log_type: String,
    /// As a rule spells it: `request.bucketName`, `resources.0.ARN`.
    pub path: String,
    #[specta(type = u32)]
    pub events: u64,
}

/// The payload paths a case holds, for the rule editor. `log_type` narrows
/// to the tab being looked at; `None` lists every type.
pub fn payload_keys(store: &Store, log_type: Option<&str>) -> Result<Vec<PayloadKey>, StoreError> {
    store.payload_keys(log_type)
}

/// Pages every event regardless of rules.
pub fn all_events(store: &Store, window: &Window) -> Result<EventPage, StoreError> {
    let mut page = store.all_events(window)?;
    if window.after.is_none() {
        page.total = Some(store.event_count_matching(window)?);
    }
    Ok(page)
}

/// A trial run: events a rule set would match, and how many were scanned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchCount {
    pub hits: u64,
    pub scanned: u64,
}

/// Events a rule set would match, without recording anything.
///
/// The editor uses this to answer "how many would this catch?" while the rule
/// is still being written: persisting a trial run would leave a half-finished
/// rule in the case's results. `scanned` comes from the same pass so the
/// answer can be read as a proportion without a second query.
///
/// `cancelled` abandons the pass; a half-counted draft is no answer, so it
/// reports [`StoreError::Cancelled`] rather than a partial total.
pub fn count_matches(
    store: &Store,
    set: &crate::rule::RuleSet,
    cancelled: impl Fn() -> bool,
) -> Result<MatchCount, StoreError> {
    let mut count = MatchCount {
        hits: 0,
        scanned: 0,
    };
    store.scan_events(
        None,
        |_| true,
        |_, log_type, event| {
            count.scanned += 1;
            // One view per event, reused across rules: building it per rule was
            // the hot path the streaming evaluator already avoids.
            if crate::rule::evaluate_any(set.for_log_type(log_type), &event) {
                count.hits += 1;
            }
        },
        cancelled,
    )?;
    Ok(count)
}

/// Runs one rule over the case and stores its matches (docs/04 lazy
/// evaluation). Reads only the columns the rule names and only the files
/// whose log type it applies to, so a narrow rule over a large case costs a
/// fraction of a full pass.
///
/// `cancelled` stops the run mid-scan. A run that did not finish leaves the
/// rule pending with no hits: hits already written are dropped once the
/// writer is gone, so the next attempt starts from scratch instead of
/// resuming into a half-scanned result.
pub fn evaluate_rule(
    store: &mut Store,
    rule: &crate::rule::Rule,
    cancelled: impl Fn() -> bool,
) -> Result<u64, StoreError> {
    store.reset_rule(rule)?;
    let set = crate::rule::RuleSet::single(rule.clone());
    let columns = rule.columns();
    // The writer handle lives only for the scan: cleanup below must not run
    // while anything can still append.
    let run = {
        let mut writer = store.writer_handle()?;
        let mut sink = |batch: &[(String, crate::rule::Hit)]| writer.append_match_batch(batch);
        let mut streamer = crate::rule::MatchStreamer::new(&set, 10_000);
        let scan = store.scan_events(
            Some(&columns),
            |log_type| rule.applies_to(log_type),
            |id, log_type, event| streamer.push_for_log_type(id, log_type, &event, &mut sink),
            &cancelled,
        );
        // Only a completed scan flushes its tail; an abandoned run drops the
        // hits it was still holding.
        match scan {
            Ok(()) => streamer
                .finish(&mut sink)
                .map_err(StoreError::RuleRun)
                .and_then(|summary| {
                    if cancelled() {
                        Err(StoreError::Cancelled)
                    } else {
                        Ok(summary)
                    }
                }),
            Err(e) => Err(e),
        }
    };
    match run {
        Ok(summary) => {
            store.mark_rule_evaluated(&rule.id)?;
            Ok(summary.rules.iter().map(|r| r.match_count).sum())
        }
        Err(e) => {
            // Partial hits would read as a finished rule in the sidebar.
            store.reset_rule(rule)?;
            Err(e)
        }
    }
}

/// One event's stored columns for the detail view.
pub fn event_fields(
    store: &Store,
    event_id: u64,
) -> Result<Vec<(String, Option<String>)>, StoreError> {
    store.event_fields(event_id)
}

/// Fetches one original record. Kept out of list queries: raw bodies are large
/// and would dominate the IPC payload (docs/03).
pub fn raw_record(store: &Store, event_id: u64) -> Result<Option<String>, StoreError> {
    store.raw_record(event_id)
}
