//! Results view queries. Aggregation runs in DuckDB so the UI never loads a
//! whole case into memory (FR-6, NFR-2).

use serde::{Deserialize, Serialize};
use specta::Type;

use crate::store::{Store, StoreError};

/// One page of rows: which slice, filtered how, ordered how. Crosses IPC as
/// one object so the commands do not grow a parameter per filter.
#[derive(Debug, Clone, Default, Deserialize, Type)]
pub struct Window {
    #[specta(type = u32)]
    pub offset: u64,
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

/// What the results window is asking for.
#[derive(Debug, Clone, Default)]
pub struct ResultQuery {
    /// `None` lists rule groups only; `Some` also pages that rule's matches.
    pub rule_id: Option<String>,
    pub window: Window,
}

#[derive(Debug, Clone, Serialize, Type)]
pub struct RuleGroup {
    pub rule_id: String,
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
    pub matches: Vec<MatchRow>,
    #[specta(type = u32)]
    pub total_matches: u64,
    #[specta(type = u32)]
    pub total_events: u64,
    #[specta(type = u32)]
    pub matched_events: u64,
    /// Events no rule matched. Shown so a coverage gap is visible, not hidden.
    #[specta(type = u32)]
    pub unmatched_events: u64,
}

/// Runs one results query against a parsed case.
///
/// Everything comes from the case database, including rule metadata, so a
/// copied case renders identically without its rule files.
pub fn query(store: &Store, request: &ResultQuery) -> Result<ResultPage, StoreError> {
    let window = &request.window;
    let (first_day, last_day) = store.day_span()?;
    let mut page = ResultPage {
        log_types: store.log_type_counts()?,
        first_day,
        last_day,
        groups: store.rule_groups(window)?,
        total_events: store.event_count(window)?,
        ..Default::default()
    };

    page.matched_events = store.matched_event_count(window)?;
    page.unmatched_events = page.total_events.saturating_sub(page.matched_events);

    if let Some(rule_id) = &request.rule_id {
        // The filtered count, not the group's: the number under the table
        // describes the list the analyst is looking at. The sidebar keeps the
        // rule's real hit count.
        page.total_matches = store.rule_match_count(rule_id, &request.window)?;
        page.matches = store.rule_matches(rule_id, &request.window)?;
    }

    Ok(page)
}

/// One page of the all-events view, with the total that page was drawn from.
#[derive(Debug, Clone, Serialize, Type, Default)]
pub struct EventPage {
    pub rows: Vec<MatchRow>,
    /// Events matching the filter. Paging needs this, or the list stops short
    /// of the filtered set or asks for pages that do not exist.
    #[specta(type = u32)]
    pub total: u64,
}

/// Pages every event regardless of rules. Separate from `query` because the
/// group list and totals do not change as the user scrolls.
pub fn all_events(store: &Store, window: &Window) -> Result<EventPage, StoreError> {
    Ok(EventPage {
        rows: store.all_events(window)?,
        total: store.event_count_matching(window)?,
    })
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
pub fn count_matches(store: &Store, set: &crate::rule::RuleSet) -> Result<MatchCount, StoreError> {
    let mut count = MatchCount {
        hits: 0,
        scanned: 0,
    };
    store.for_each_typed_event(|_, log_type, event| {
        count.scanned += 1;
        // One view per event, reused across rules: building it per rule was
        // the hot path the streaming evaluator already avoids.
        if crate::rule::evaluate_any(set.for_log_type(log_type), &event) {
            count.hits += 1;
        }
    })?;
    Ok(count)
}

/// Runs one rule over the case and stores its matches (docs/04 lazy
/// evaluation). Reads only the columns the rule names and only the files
/// whose log type it applies to, so a narrow rule over a large case costs a
/// fraction of a full pass.
pub fn evaluate_rule(store: &mut Store, rule: &crate::rule::Rule) -> Result<u64, StoreError> {
    store.reset_rule(rule)?;
    let set = crate::rule::RuleSet::single(rule.clone());
    let mut writer = store.writer_handle()?;
    let mut sink = |batch: &[(String, crate::rule::Hit)]| writer.append_match_batch(batch);
    let mut streamer = crate::rule::MatchStreamer::new(&set, 10_000);
    let columns = rule.columns();
    store.scan_events(
        Some(&columns),
        |log_type| rule.applies_to(log_type),
        |id, log_type, event| streamer.push_for_log_type(id, log_type, &event, &mut sink),
    )?;
    let summary = streamer.finish(&mut sink).map_err(StoreError::RuleRun)?;
    store.mark_rule_evaluated(&rule.id)?;
    Ok(summary.rules.iter().map(|r| r.match_count).sum())
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
