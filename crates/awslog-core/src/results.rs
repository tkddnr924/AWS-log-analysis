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
/// rule in the case's results. The pass reads only the columns the set names
/// and only the files some rule applies to, and lets DuckDB drop rows no rule
/// can match; `scanned` still counts every event the case holds, so the
/// answer reads as a proportion of the case without a second query.
///
/// `cancelled` abandons the pass; a half-counted draft is no answer, so it
/// reports [`StoreError::Cancelled`] rather than a partial total.
pub fn count_matches(
    store: &Store,
    set: &crate::rule::RuleSet,
    cancelled: impl Fn() -> bool,
) -> Result<MatchCount, StoreError> {
    let mut hits = 0;
    let rules: Vec<&crate::rule::Rule> = set.rules().iter().collect();
    let scanned = store.scan_rule_candidates(
        &rules,
        |_, log_type, event| {
            // One view per event, reused across rules: building it per rule was
            // the hot path the streaming evaluator already avoids.
            if crate::rule::evaluate_any(set.for_log_type(log_type), &event) {
                hits += 1;
            }
        },
        cancelled,
    )?;
    Ok(MatchCount { hits, scanned })
}

/// Runs one rule over the case and stores its matches (docs/04 lazy
/// evaluation). Reads only the columns the rule names, only the files whose
/// log type it applies to and, where the rule's condition allows it safely,
/// only the rows that can satisfy it, so a narrow rule over a large case
/// costs a fraction of a full pass.
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
    match record_matches(store, rule, &cancelled) {
        Ok(hits) => {
            store.mark_rule_evaluated(&rule.id)?;
            Ok(hits)
        }
        Err(e) => {
            // Partial hits would read as a finished rule in the sidebar.
            store.reset_rule(rule)?;
            Err(e)
        }
    }
}

/// Scans for `rule` and appends its hits; returns their number. Leaves
/// registering the rule, and clearing up after a failure, to the caller.
fn record_matches(
    store: &mut Store,
    rule: &crate::rule::Rule,
    cancelled: &impl Fn() -> bool,
) -> Result<u64, StoreError> {
    let set = crate::rule::RuleSet::single(rule.clone());
    // The writer handle lives only for the scan: the caller's cleanup must
    // not run while anything can still append.
    let mut writer = store.writer_handle()?;
    let mut sink = |batch: &[(String, crate::rule::Hit)]| writer.append_match_batch(batch);
    let mut streamer = crate::rule::MatchStreamer::new(&set, 10_000);
    store.scan_rule_candidates(
        &[rule],
        |id, log_type, event| streamer.push_for_log_type(id, log_type, &event, &mut sink),
        cancelled,
    )?;
    // Only a completed scan flushes its tail; an abandoned run drops the
    // hits it was still holding.
    let summary = streamer.finish(&mut sink).map_err(StoreError::RuleRun)?;
    if cancelled() {
        return Err(StoreError::Cancelled);
    }
    Ok(summary.rules.iter().map(|r| r.match_count).sum())
}

/// How often each value of one field occurs in the list being looked at
/// (`Store::field_stats`). `values` is the 200 most frequent or fewer;
/// `total` and `distinct` count all rows and all values.
#[derive(Debug, Clone, Serialize, Type)]
pub struct FieldStats {
    pub field: String,
    #[specta(type = u32)]
    pub total: u64,
    #[specta(type = u32)]
    pub distinct: u64,
    pub values: Vec<FieldCount>,
}

#[derive(Debug, Clone, Serialize, Type)]
pub struct FieldCount {
    /// `None`: the field is absent or null on those rows.
    pub value: Option<String>,
    #[specta(type = u32)]
    pub count: u64,
}

/// Per-value counts of `field` over the list the window shows: every event,
/// or the matches of `rule_id` (a rule, or [`SEARCH_RULE_ID`]).
pub fn field_stats(
    store: &Store,
    rule_id: Option<&str>,
    field: &str,
    window: &Window,
) -> Result<FieldStats, StoreError> {
    store.field_stats(rule_id, field, window)
}

/// The rule id condition-search hits are stored under. `#` cannot start a
/// rule identifier, so no rule shares it, and it is never registered in
/// `rules`: the sidebar does not list it and case totals leave it out.
pub const SEARCH_RULE_ID: &str = "#search";

/// Runs a condition typed into the results search (`rule::parse_condition`)
/// and stores its hits under [`SEARCH_RULE_ID`], replacing the previous
/// search, so they page, count and filter exactly like a rule's matches.
///
/// `within` narrows to one rule's matches: the stored condition is that
/// rule's `and` the query, scoped to the rule's log type. The query's
/// variables are renamed `search:<name>` so they cannot merge with the
/// rule's — one name means "either condition holds".
pub fn search_condition(
    store: &mut Store,
    within: Option<&crate::rule::Rule>,
    query: &crate::rule::Rule,
    cancelled: impl Fn() -> bool,
) -> Result<u64, StoreError> {
    use crate::rule::{Condition, Rule};

    let rule = match within {
        None => Rule {
            id: SEARCH_RULE_ID.to_owned(),
            meta: Default::default(),
            fields: query.fields.clone(),
            condition: query.condition.clone(),
        },
        Some(scope) => {
            fn renamed(condition: &Condition) -> Condition {
                let var = |name: &String| format!("search:{name}");
                match condition {
                    Condition::Var(name) => Condition::Var(var(name)),
                    Condition::Not(inner) => Condition::Not(Box::new(renamed(inner))),
                    Condition::And(a, b) => {
                        Condition::And(Box::new(renamed(a)), Box::new(renamed(b)))
                    }
                    Condition::Or(a, b) => {
                        Condition::Or(Box::new(renamed(a)), Box::new(renamed(b)))
                    }
                    Condition::NOf(count, vars) => {
                        Condition::NOf(*count, vars.iter().map(var).collect())
                    }
                }
            }
            let mut fields = scope.fields.clone();
            fields.extend(query.fields.iter().map(|field| {
                let mut field = field.clone();
                field.var = format!("search:{}", field.var);
                field
            }));
            Rule {
                id: SEARCH_RULE_ID.to_owned(),
                meta: scope
                    .meta
                    .get("log_type")
                    .map(|t| ("log_type".to_owned(), t.clone()))
                    .into_iter()
                    .collect(),
                fields,
                condition: Condition::And(
                    Box::new(scope.condition.clone()),
                    Box::new(renamed(&query.condition)),
                ),
            }
        }
    };
    // Never registered: the previous search's hits go, and so do a failed
    // run's partial ones.
    store.remove_rule(SEARCH_RULE_ID)?;
    record_matches(store, &rule, &cancelled).inspect_err(|_| {
        let _ = store.remove_rule(SEARCH_RULE_ID);
    })
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
