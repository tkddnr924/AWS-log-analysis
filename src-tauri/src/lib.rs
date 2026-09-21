//! Tauri shell. Thin IPC adapter over `awslog-core`; no analysis logic here.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use awslog_core::logging::{AppLog, CaseLog};
use awslog_core::mapping::{Field, FieldMap};
use awslog_core::parse::{self, ParseOptions};
use awslog_core::paths::{self, CasesRoot, RootSources};
use awslog_core::report::{self, DetectionRow, ScanSummary};
use awslog_core::results::{self, ResultPage};
use awslog_core::rule::RuleSet;
use awslog_core::scan;
use awslog_core::store::{CaseStatus, Store};
use parking_lot::Mutex;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_specta::{collect_commands, collect_events, Builder, Event};
use time::{OffsetDateTime, PrimitiveDateTime};

/// Tracks the single in-flight scan of a case — a parse, a rule evaluation
/// or a draft count. Only one may run per process: the case directory, the
/// store and the cancel flag are all per-run, and they write one database.
///
/// Cloning shares the slot, so every clone of `AppState` sees one claim.
#[derive(Clone, Default)]
struct ParseSlot(Arc<Mutex<Option<Arc<AtomicBool>>>>);

impl ParseSlot {
    /// Claims the slot. `None` means one is already running — refusing is
    /// the only safe answer, since overwriting would strand the first run's
    /// cancel flag where `cancel` can no longer reach it.
    ///
    /// The returned guard frees the slot on drop, so an early `?` or a panic
    /// inside the worker cannot leave it claimed forever.
    fn begin(&self) -> Option<ParseRun> {
        let mut slot = self.0.lock();
        if slot.is_some() {
            return None;
        }
        let flag = Arc::new(AtomicBool::new(false));
        *slot = Some(flag.clone());
        Some(ParseRun {
            slot: self.clone(),
            flag,
        })
    }

    /// Cooperative cancel; a no-op when nothing is running.
    fn cancel(&self) {
        if let Some(flag) = self.0.lock().as_ref() {
            flag.store(true, Ordering::Relaxed);
        }
    }
}

/// Refusal when the slot is taken. The parse and every rule scan share it.
const SLOT_BUSY: &str = "파싱 또는 룰 평가가 진행 중입니다";

/// An event id crossing IPC. Ids are `(file_id << 32) | record_index`, so
/// anything past the first file exceeds u32. specta refuses u64, and the
/// value is exact in a JS number below 2^53 (file ids stay far under 2^21).
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(transparent)]
struct EventId(u64);

impl specta::Type for EventId {
    fn definition(types: &mut specta::Types) -> specta::datatype::DataType {
        <f64 as specta::Type>::definition(types)
    }
}

/// Holds the slot for as long as one run is in flight. A worker owns its
/// guard, so the slot frees when the worker itself exits — not when the IPC
/// future that spawned it is dropped while the work goes on.
struct ParseRun {
    slot: ParseSlot,
    flag: Arc<AtomicBool>,
}

impl ParseRun {
    /// The predicate core scans poll to stop early.
    fn cancelled(&self) -> impl Fn() -> bool {
        let flag = self.flag.clone();
        move || flag.load(Ordering::Relaxed)
    }
}

impl Drop for ParseRun {
    fn drop(&mut self) {
        *self.slot.0.lock() = None;
    }
}

/// The open database instance of a case. Only ever used to spawn handles;
/// the mutex exists because `Store` is not `Sync`.
struct CaseDb(Mutex<Store>);

/// A connection to a case's database. Keeps the instance it came from alive,
/// so a command still running on a case that was meanwhile switched away
/// from and back gets the same instance, never a second one.
struct CaseHandle {
    store: Store,
    _db: Arc<CaseDb>,
}

impl std::ops::Deref for CaseHandle {
    type Target = Store;
    fn deref(&self) -> &Store {
        &self.store
    }
}

impl std::ops::DerefMut for CaseHandle {
    fn deref_mut(&mut self) -> &mut Store {
        &mut self.store
    }
}

/// One database instance per case file per process.
///
/// duckdb-rs opens through `duckdb_open_ext`, which bypasses DuckDB's
/// instance cache: every `Store::open` on the same file is an independent
/// database instance. Two instances on one file in one process are refused
/// on Windows ("conflicting lock is held in <this exe>") and on Unix they
/// silently stop seeing each other's writes. So a case is opened once and
/// every command works on a `try_clone` handle of that instance.
///
/// `current` keeps the most recently used case open between commands; one
/// only, since each instance may hold up to `memory_limit` of cached blocks
/// and the UI shows one case at a time. `live` finds instances that handles
/// in flight still hold after `current` moved on.
#[derive(Default)]
struct StoreCache(Mutex<CacheState>);

#[derive(Default)]
struct CacheState {
    current: Option<(String, Arc<CaseDb>)>,
    live: std::collections::HashMap<String, std::sync::Weak<CaseDb>>,
}

impl StoreCache {
    /// A handle on the case's database, opening it on first use.
    fn open(
        &self,
        case_id: &str,
        open: impl FnOnce() -> Result<Store, String>,
    ) -> Result<CaseHandle, String> {
        let mut state = self.0.lock();
        let db = match state.live.get(case_id).and_then(std::sync::Weak::upgrade) {
            Some(db) => db,
            None => {
                // Drop the previous case before opening: two idle instances
                // would double the buffer pool ceiling.
                state.current = None;
                state.live.retain(|_, weak| weak.strong_count() > 0);
                let db = Arc::new(CaseDb(Mutex::new(open()?)));
                state.live.insert(case_id.to_owned(), Arc::downgrade(&db));
                db
            }
        };
        if !matches!(&state.current, Some((id, _)) if id == case_id) {
            state.current = Some((case_id.to_owned(), db.clone()));
        }
        // A second connection on the same instance; readers use it too.
        let store = db.0.lock().writer_handle().map_err(|e| e.to_string())?;
        Ok(CaseHandle { store, _db: db })
    }

    /// Deletes a case's files, or refuses while a command still holds its
    /// database. `remove_dir_all` takes `case.json` and `rules/` before it
    /// reaches the locked `session.duckdb` on Windows, so letting the OS
    /// refuse would leave a half-deleted case. Runs under the cache lock so
    /// no handle can be opened in the meantime.
    fn delete(
        &self,
        case_id: &str,
        delete: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let mut state = self.0.lock();
        if matches!(&state.current, Some((id, _)) if id == case_id) {
            state.current = None;
        }
        if state
            .live
            .get(case_id)
            .is_some_and(|w| w.strong_count() > 0)
        {
            return Err("케이스가 아직 사용 중입니다. 작업이 끝난 뒤 다시 시도하세요".to_owned());
        }
        state.live.remove(case_id);
        delete()
    }
}

/// Startup state shared with commands. Cloned into blocking workers.
#[derive(Clone)]
struct AppState {
    cases_root: CasesRoot,
    parse: ParseSlot,
    stores: Arc<StoreCache>,
}

impl AppState {
    /// Opens a case's store with spills kept inside the case (docs/07).
    fn store(&self, case_id: &str) -> Result<CaseHandle, String> {
        let case_dir = self
            .cases_root
            .case_dir(case_id)
            .ok_or_else(|| format!("잘못된 케이스 id: {case_id}"))?;
        self.stores.open(case_id, || {
            let store = Store::open(&case_dir.join("session.duckdb")).map_err(|e| e.to_string())?;
            store.set_temp_dir(&case_dir).map_err(|e| e.to_string())?;
            Ok(store)
        })
    }
}

#[tauri::command]
#[specta::specta]
fn cases_root(state: tauri::State<'_, AppState>) -> String {
    state.cases_root.path().display().to_string()
}

/// FR-2: list supported gzip log candidates without reading their contents.
/// Async so Tauri runs it off the main thread — a bucket export can hold tens
/// of thousands of files and the walk must not freeze the window (NFR-3).
#[tauri::command]
#[specta::specta]
async fn scan_directory(path: String) -> Result<ScanSummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let report = scan::scan_dir(Path::new(&path)).map_err(|e| e.to_string())?;
        Ok(report::summarize_scan(&report))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Progress while classifying candidates.
#[derive(Clone, serde::Serialize, specta::Type, tauri_specta::Event)]
struct DetectProgress {
    done: u32,
    total: u32,
}

/// FR-3/FR-4: classify each candidate and return one sample record per file.
/// Files are decoded in parallel; progress is emitted so the UI can show
/// movement instead of waiting for one large response.
#[tauri::command]
#[specta::specta]
async fn detect_logs(app: tauri::AppHandle, path: String) -> Result<Vec<DetectionRow>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = PathBuf::from(&path);
        let report = scan::scan_dir(&root).map_err(|e| e.to_string())?;

        // Emit at most every 32 files: one event per file would flood IPC.
        let emit = |done: usize, total: usize| {
            if done % 32 == 0 || done == total {
                let _ = DetectProgress {
                    done: done as u32,
                    total: total as u32,
                }
                .emit(&app);
            }
        };
        Ok(report::detect_all_with_progress(&root, &report, &emit))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Progress while parsing into the session store.
#[derive(Clone, serde::Serialize, specta::Type, tauri_specta::Event)]
struct ParseProgress {
    files_done: u32,
    files_total: u32,
    records_parsed: u32,
    /// True once cancellation was requested, so the UI can lock the button
    /// instead of firing the command repeatedly.
    cancel_requested: bool,
}

/// Result of one parse run, shown when it finishes.
#[derive(Clone, serde::Serialize, specta::Type)]
struct ParseResult {
    case_id: String,
    files_parsed: u32,
    files_skipped: u32,
    files_failed: u32,
    records_parsed: u32,
    cancelled: bool,
}

/// One row of the mapping editor: a column, its display name and the JSON
/// paths feeding it. `label` travels with the row so the UI never keeps its
/// own copy of the names — see `Field::label`.
#[derive(Clone, serde::Serialize, serde::Deserialize, specta::Type)]
struct MappingEntry {
    field: String,
    label: String,
    sources: Vec<String>,
}

fn build_map(entries: &[MappingEntry]) -> FieldMap {
    let mut map = FieldMap::cloudtrail();
    for entry in entries {
        if let Some(field) = Field::from_key(&entry.field) {
            map.set(field, entry.sources.clone());
        }
    }
    map
}

/// The mapping the editor starts from, so the UI never hard-codes AWS paths.
#[tauri::command]
#[specta::specta]
fn default_mapping() -> Vec<MappingEntry> {
    let map = FieldMap::cloudtrail();
    Field::ALL
        .into_iter()
        .map(|field| MappingEntry {
            field: field.key().to_owned(),
            label: field.label().to_owned(),
            sources: map.sources(field).into_iter().map(str::to_owned).collect(),
        })
        .collect()
}

/// Resolves a mapping against one sample record. The editor previews through
/// the same resolver the parser uses, so what is shown is what gets stored.
#[tauri::command]
#[specta::specta]
fn preview_mapping(
    record: String,
    mapping: Vec<MappingEntry>,
) -> Result<Vec<FieldPreview>, String> {
    let value: serde_json::Value = serde_json::from_str(&record).map_err(|e| e.to_string())?;
    let map = build_map(&mapping);
    Ok(Field::ALL
        .into_iter()
        .map(|field| FieldPreview {
            field: field.key().to_owned(),
            label: field.label().to_owned(),
            value: map.lookup(&value, field).map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            }),
        })
        .collect())
}

/// FR-4: the head of one detected file as pieces with the column each one
/// feeds, under the editor's current mapping (docs/03 "포맷 카드").
/// `display_path` is the detection row's path, relative to `root`.
#[tauri::command]
#[specta::specta]
async fn preview_head(
    root: String,
    display_path: String,
    log_type: String,
    mapping: Vec<MappingEntry>,
) -> Result<awslog_core::preview::HeadPreview, String> {
    let root = PathBuf::from(root);
    let path = root.join(&display_path);
    // The row came from scanning `root`; anything else is not ours to read.
    if display_path.split('/').any(|part| part == "..") || !path.starts_with(&root) {
        return Err(format!("파일이 스캔한 폴더 밖입니다: {display_path}"));
    }
    let log_type = awslog_core::detect::LogType::parse(&log_type)
        .ok_or_else(|| format!("알 수 없는 로그 타입: {log_type}"))?;
    let map = build_map(&mapping);
    tauri::async_runtime::spawn_blocking(move || {
        awslog_core::preview::preview_head(&path, log_type, &map).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// One resolved field: `None` means no source path matched.
#[derive(Clone, serde::Serialize, specta::Type)]
struct FieldPreview {
    field: String,
    label: String,
    value: Option<String>,
}

/// FR-5: create a case and parse the directory into its session database.
/// Cancellation is cooperative; partial results stay on disk.
#[tauri::command]
#[specta::specta]
async fn start_parse(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
    selected: Vec<String>,
    mapping: Vec<MappingEntry>,
) -> Result<ParseResult, String> {
    let mapping = build_map(&mapping);
    let state = state.inner().clone();
    // Claimed before the worker spawns and moved into it below: the slot
    // frees when the parse itself stops, not when this future is dropped.
    let Some(run) = state.parse.begin() else {
        return Err("이미 파싱이 진행 중입니다".to_owned());
    };

    let result = tauri::async_runtime::spawn_blocking(move || {
        let cancel = run.flag.clone();
        let input = PathBuf::from(&path);
        let now = OffsetDateTime::now_utc();
        let started = PrimitiveDateTime::new(now.date(), now.time());
        let case = state
            .cases_root
            .create_case(&input, started)
            .map_err(|e| e.to_string())?;

        let case_log = CaseLog::open(&case).map_err(|e| e.to_string())?;
        case_log.info(&format!("parse started input={}", input.display()));

        // Snapshot the mapping beside the rules: a result has to stay
        // explainable, and that needs the paths the columns came from.
        let mapping_json = serde_json::to_string_pretty(&mapping).map_err(|e| e.to_string())?;
        std::fs::write(case.dir().join("mapping.json"), mapping_json).map_err(|e| e.to_string())?;

        // Cached so the results view that follows reuses this instance
        // instead of closing and reopening the file.
        let mut store = state.stores.open(case.id(), || {
            let store = Store::create(&case.session_db(), case.id(), &input.display().to_string())
                .map_err(|e| e.to_string())?;
            // Keep DuckDB spill files inside the case (docs/07).
            store.set_temp_dir(case.dir()).map_err(|e| e.to_string())?;
            Ok(store)
        })?;

        let options = ParseOptions {
            cancel: Some(cancel.clone()),
            selected: Some(selected.into_iter().collect()),
            mapping,
            ..Default::default()
        };
        let emit = |p: awslog_core::parse::Progress| {
            let _ = ParseProgress {
                files_done: p.files_done as u32,
                files_total: p.files_total as u32,
                records_parsed: p.records_parsed as u32,
                cancel_requested: cancel.load(std::sync::atomic::Ordering::Relaxed),
            }
            .emit(&app);
        };

        let run = parse::run(&input, &mut store, &options, &emit);

        // A failed run must not leave the case stuck in `running`: record a
        // terminal status and refresh case.json before returning the error.
        let outcome = match run {
            Ok(outcome) => outcome,
            Err(e) => {
                let message = e.to_string();
                case_log.info(&format!("parse failed: {message}"));
                let _ = store.finish(CaseStatus::Failed);
                let _ = store.write_case_json(case.dir());
                return Err(message);
            }
        };

        for failure in &outcome.failures {
            case_log.warn_file_skipped(Path::new(&failure.display_path), &failure.reason);
        }

        // Rules are only registered here; each is evaluated over the stored
        // events when the analyst first opens it (docs/04 lazy evaluation).
        match register_rules(&mut store, &state.cases_root.user_rules_dir(), case.dir()) {
            Ok(count) => case_log.info(&format!("rules registered {count}")),
            Err(e) => case_log.info(&format!("rule registration failed: {e}")),
        }

        let status = if outcome.cancelled {
            CaseStatus::Cancelled
        } else {
            CaseStatus::Done
        };
        store.finish(status).map_err(|e| e.to_string())?;
        store
            .write_case_json(case.dir())
            .map_err(|e| e.to_string())?;
        case_log.info(&format!(
            "parse finished records={} failed={}",
            outcome.records_parsed, outcome.files_failed
        ));

        Ok::<_, String>(ParseResult {
            case_id: case.id().to_string(),
            files_parsed: outcome.files_parsed as u32,
            files_skipped: outcome.files_skipped as u32,
            files_failed: outcome.files_failed as u32,
            records_parsed: outcome.records_parsed as u32,
            cancelled: outcome.cancelled,
        })
    })
    .await
    .map_err(|e| e.to_string())?;

    result
}

/// Preferred window size, reduced to fit the monitor.
///
/// `work_area()` excludes the taskbar/dock, and the value is physical pixels,
/// so it is divided by the scale factor to compare with the logical size the
/// builder takes. An earlier attempt used `size()` and mis-read the scale on
/// Retina, which is why the work area is used here instead.
fn window_size(app: &tauri::App) -> (f64, f64) {
    let Ok(Some(monitor)) = app.primary_monitor() else {
        return PREFERRED_WINDOW;
    };
    let scale = monitor.scale_factor();
    let area = monitor.work_area();
    fit_window(
        f64::from(area.size.width) / scale,
        f64::from(area.size.height) / scale,
    )
}

const PREFERRED_WINDOW: (f64, f64) = (1440.0, 900.0);
const MIN_WINDOW: (f64, f64) = (960.0, 640.0);

/// The arithmetic, separated so it can be checked against screen sizes this
/// machine does not have. A margin is kept so the window stays grabbable.
fn fit_window(area_width: f64, area_height: f64) -> (f64, f64) {
    (
        PREFERRED_WINDOW.0.min(area_width - 48.0).max(MIN_WINDOW.0),
        PREFERRED_WINDOW.1.min(area_height - 48.0).max(MIN_WINDOW.1),
    )
}

/// Loads the shipped pack plus the user rules, snapshots them into the case,
/// and registers every rule as pending. Returns how many were registered.
fn register_rules(store: &mut Store, user_dir: &Path, case_dir: &Path) -> Result<usize, String> {
    let set = RuleSet::load_layered(user_dir).map_err(|e| e.to_string())?;
    // Snapshot first: a result must stay explainable after rules change.
    RuleSet::snapshot_into(user_dir, &case_dir.join("rules")).map_err(|e| e.to_string())?;
    store
        .writer_handle()
        .map_err(|e| e.to_string())?
        .begin_rule_run(set.rules())
        .map_err(|e| e.to_string())?;
    Ok(set.rules().len())
}

/// Claims the shared slot for a rule scan, then signals `started`.
///
/// The order is the contract with the UI: the claim stands before the caller
/// hears the scan began, so a `cancel_parse` sent on leaving the results view
/// always finds this run. Nothing can be lost between `invoke` and the
/// worker spawning.
fn begin_rule_scan(
    slot: &ParseSlot,
    started: impl FnOnce() -> Result<(), String>,
) -> Result<ParseRun, String> {
    let run = slot.begin().ok_or_else(|| SLOT_BUSY.to_owned())?;
    started()?;
    Ok(run)
}

/// Runs one rule over the case and stores its matches. Holds the parse
/// slot: it writes to the same database a parse would. `started` fires once
/// that slot is held, telling the UI a cancel will now land.
#[tauri::command]
#[specta::specta]
async fn evaluate_rule(
    state: tauri::State<'_, AppState>,
    case_id: String,
    rule_id: String,
    started: tauri::ipc::Channel<()>,
) -> Result<u32, String> {
    let state = state.inner().clone();
    let run = begin_rule_scan(&state.parse, || started.send(()).map_err(|e| e.to_string()))?;
    tauri::async_runtime::spawn_blocking(move || {
        // The guard moves into the worker, so the slot frees when the scan
        // stops — a cancelled evaluation never blocks the next parse.
        evaluate_rule_in(&state, &case_id, &rule_id, run.cancelled()).map(|hits| hits as u32)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Scans the case for one rule. The slot claim belongs to the caller: it
/// has to be held from before the worker spawns until the worker exits.
fn evaluate_rule_in(
    state: &AppState,
    case_id: &str,
    rule_id: &str,
    cancelled: impl Fn() -> bool,
) -> Result<u64, String> {
    let set =
        RuleSet::load_layered(&state.cases_root.user_rules_dir()).map_err(|e| e.to_string())?;
    let rule = set
        .rule(rule_id)
        .ok_or_else(|| format!("룰을 찾을 수 없습니다: {rule_id}"))?;
    let mut store = state.store(case_id)?;
    results::evaluate_rule(&mut store, rule, cancelled).map_err(|e| e.to_string())
}

/// Lists rule groups and totals for a case. The window's log type and date
/// range narrow everything, group counts included; its search is ignored.
/// Rows are paged by `query_rule_matches` and `query_events`, so scrolling
/// never repeats the case-level scans this does.
#[tauri::command]
#[specta::specta]
async fn query_results(
    state: tauri::State<'_, AppState>,
    case_id: String,
    window: results::Window,
) -> Result<ResultPage, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || query_results_in(&state, &case_id, &window))
        .await
        .map_err(|e| e.to_string())?
}

fn query_results_in(
    state: &AppState,
    case_id: &str,
    window: &results::Window,
) -> Result<ResultPage, String> {
    let case_dir = state
        .cases_root
        .case_dir(case_id)
        .ok_or_else(|| format!("invalid case id: {case_id}"))?;
    let mut store = state.store(case_id)?;
    // Cases recorded before `rules.log_type` / `rules.name` existed: fill
    // them from the rule snapshot so the sidebar can scope and label rules
    // without re-evaluating. Older cases may have no snapshot either; the
    // current rules are the next best description of what was evaluated.
    let lacking = |store: &Store| -> Result<bool, String> {
        Ok(store.rules_lack_log_type().map_err(|e| e.to_string())?
            || store.rules_lack_name().map_err(|e| e.to_string())?)
    };
    if lacking(&store)? {
        let candidates = [
            RuleSet::load_dir(&case_dir.join("rules")),
            RuleSet::load_layered(&state.cases_root.user_rules_dir()),
        ];
        for set in candidates.into_iter().flatten() {
            store
                .backfill_rule_log_types(set.rules())
                .map_err(|e| e.to_string())?;
            store
                .backfill_rule_names(set.rules())
                .map_err(|e| e.to_string())?;
            if !lacking(&store)? {
                break;
            }
        }
    }
    results::query(&store, window).map_err(|e| e.to_string())
}

/// One cursor page of a rule's matches, read from the match table alone.
/// The filtered count is computed only for the first page.
#[tauri::command]
#[specta::specta]
async fn query_rule_matches(
    state: tauri::State<'_, AppState>,
    case_id: String,
    rule_id: String,
    window: results::Window,
) -> Result<results::EventPage, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = state.store(&case_id)?;
        results::rule_matches(&store, &rule_id, &window).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The payload paths a case's events hold (`request.*`, `response.*`,
/// `resources.*`), counted while parsing, so the rule editor can offer what
/// the data has instead of a fixed field list. `log_type` narrows to the
/// tab being looked at.
#[tauri::command]
#[specta::specta]
async fn list_payload_keys(
    state: tauri::State<'_, AppState>,
    case_id: String,
    log_type: Option<String>,
) -> Result<Vec<results::PayloadKey>, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = state.store(&case_id)?;
        results::payload_keys(&store, log_type.as_deref()).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Fetches one original record on demand (never in list payloads).
#[tauri::command]
#[specta::specta]
async fn get_raw_record(
    state: tauri::State<'_, AppState>,
    case_id: String,
    event_id: EventId,
) -> Result<Option<String>, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = state.store(&case_id)?;
        results::raw_record(&store, event_id.0).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// One effective rule's text. Saving any rule writes a user rule, which
/// overrides a shipped rule with the same id (docs/04 rule layering).
#[derive(Clone, serde::Serialize, specta::Type)]
struct RuleSource {
    rule_id: String,
    source: String,
    /// Came from `cases/rules/`: deleting it removes the file too.
    user: bool,
}

/// Path of one user rule under `cases/rules/`. The id is validated the same
/// way case ids are: it becomes a filename.
fn user_rule_path(user_dir: &Path, rule_id: &str) -> Result<PathBuf, String> {
    if !paths::is_safe_case_id(rule_id) {
        return Err(format!("사용할 수 없는 룰 이름입니다: {rule_id}"));
    }
    Ok(user_dir.join(format!("{rule_id}.yar")))
}

/// Writes one user rule. One rule per file, named after its id, so deleting
/// the rule is deleting the file.
fn write_user_rule(user_dir: &Path, source: &str) -> Result<String, String> {
    // Parse before writing: an invalid rule must not reach disk, where it
    // would break every later load_layered.
    let set = RuleSet::from_source(source).map_err(|e| e.to_string())?;
    let [rule] = set.rules() else {
        return Err("한 번에 룰 하나만 저장할 수 있습니다".to_owned());
    };
    let rule_id = rule.id.clone();
    let path = user_rule_path(user_dir, &rule_id)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, source).map_err(|e| e.to_string())?;
    Ok(rule_id)
}

/// Every effective rule's text, so the editor can open any of them.
#[tauri::command]
#[specta::specta]
async fn list_rule_sources(state: tauri::State<'_, AppState>) -> Result<Vec<RuleSource>, String> {
    let cases_root = state.cases_root.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let set = RuleSet::load_layered(&cases_root.user_rules_dir()).map_err(|e| e.to_string())?;
        let mut rules: Vec<RuleSource> = set
            .rules()
            .iter()
            .filter_map(|rule| {
                Some(RuleSource {
                    rule_id: rule.id.clone(),
                    source: set.source(&rule.id)?.to_owned(),
                    user: set.is_user(&rule.id),
                })
            })
            .collect();
        rules.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        Ok(rules)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Validates and stores one user rule, refreshes the case snapshot and
/// registers the rule as pending in the case: selecting it evaluates it.
#[tauri::command]
#[specta::specta]
async fn save_rule(
    state: tauri::State<'_, AppState>,
    case_id: String,
    source: String,
) -> Result<String, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || save_rule_in(&state, &case_id, &source))
        .await
        .map_err(|e| e.to_string())?
}

fn save_rule_in(state: &AppState, case_id: &str, source: &str) -> Result<String, String> {
    let _run = state.parse.begin().ok_or_else(|| SLOT_BUSY.to_owned())?;
    let user_dir = state.cases_root.user_rules_dir();
    let rule_id = write_user_rule(&user_dir, source)?;
    let set = RuleSet::load_layered(&user_dir).map_err(|e| e.to_string())?;
    let rule = set
        .rule(&rule_id)
        .ok_or_else(|| format!("저장한 룰을 다시 읽지 못했습니다: {rule_id}"))?;
    let case_dir = state
        .cases_root
        .case_dir(case_id)
        .ok_or_else(|| format!("잘못된 케이스 id: {case_id}"))?;
    RuleSet::snapshot_into(&user_dir, &case_dir.join("rules")).map_err(|e| e.to_string())?;
    state
        .store(case_id)?
        .reset_rule(rule)
        .map_err(|e| e.to_string())?;
    Ok(rule_id)
}

/// Removes a rule from this case. A user rule's file goes too (the shipped
/// rule it overrode, if any, is back for the next case); a shipped rule
/// stays in the pack and only leaves this case's results.
#[tauri::command]
#[specta::specta]
async fn delete_rule(
    state: tauri::State<'_, AppState>,
    case_id: String,
    rule_id: String,
) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || delete_rule_in(&state, &case_id, &rule_id))
        .await
        .map_err(|e| e.to_string())?
}

fn delete_rule_in(state: &AppState, case_id: &str, rule_id: &str) -> Result<(), String> {
    let _run = state.parse.begin().ok_or_else(|| SLOT_BUSY.to_owned())?;
    let user_dir = state.cases_root.user_rules_dir();
    let path = user_rule_path(&user_dir, rule_id)?;
    if path.is_file() {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        let case_dir = state
            .cases_root
            .case_dir(case_id)
            .ok_or_else(|| format!("잘못된 케이스 id: {case_id}"))?;
        RuleSet::snapshot_into(&user_dir, &case_dir.join("rules")).map_err(|e| e.to_string())?;
    }
    state
        .store(case_id)?
        .remove_rule(rule_id)
        .map_err(|e| e.to_string())
}

/// What a draft rule says, in words, plus its id and metadata. The editor
/// shows this beside the source so intent can be checked without re-reading
/// the syntax.
#[derive(Clone, Debug, serde::Serialize, specta::Type)]
struct RuleOutline {
    rule_id: String,
    /// `meta: name`, or the id when the draft has none.
    name: String,
    description: String,
    severity: String,
    /// The condition rendered as a sentence.
    explanation: String,
}

/// Why a draft does not parse, and where. `line` is what the editor marks
/// in the gutter; it is absent for errors that are not a place in the text
/// (a duplicate id, two rules in one draft).
#[derive(Clone, Debug, serde::Serialize, specta::Type)]
struct RuleProblem {
    message: String,
    line: Option<u32>,
}

#[tauri::command]
#[specta::specta]
fn explain_rule(source: String) -> Result<RuleOutline, RuleProblem> {
    let set = RuleSet::from_source(&source).map_err(|e| RuleProblem {
        message: e.to_string(),
        line: e.line().map(|l| l as u32),
    })?;
    let [rule] = set.rules() else {
        return Err(RuleProblem {
            message: "한 번에 룰 하나만 편집할 수 있습니다".to_owned(),
            line: None,
        });
    };
    Ok(RuleOutline {
        rule_id: rule.id.clone(),
        name: rule.name().to_owned(),
        description: rule.description().to_owned(),
        severity: rule.severity().to_owned(),
        explanation: awslog_core::rule::explain(rule),
    })
}

/// Events a draft rule would match, without saving it or disturbing the
/// case's recorded matches. A trial run scans the case, so it takes the same
/// slot as an evaluation and stops on the same cancel; `started` fires once
/// the slot is held.
#[tauri::command]
#[specta::specta]
async fn count_rule_matches(
    state: tauri::State<'_, AppState>,
    case_id: String,
    source: String,
    started: tauri::ipc::Channel<()>,
) -> Result<RuleHits, String> {
    let state = state.inner().clone();
    let run = begin_rule_scan(&state.parse, || started.send(()).map_err(|e| e.to_string()))?;
    tauri::async_runtime::spawn_blocking(move || {
        count_rule_matches_in(&state, &case_id, &source, run.cancelled())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Counts a draft's matches under the caller's slot claim.
fn count_rule_matches_in(
    state: &AppState,
    case_id: &str,
    source: &str,
    cancelled: impl Fn() -> bool,
) -> Result<RuleHits, String> {
    let set = RuleSet::from_source(source).map_err(|e| e.to_string())?;
    let store = state.store(case_id)?;
    let count = results::count_matches(&store, &set, cancelled).map_err(|e| e.to_string())?;
    Ok(RuleHits {
        hits: count.hits as u32,
        total: count.scanned as u32,
    })
}

/// A trial run's result: matches out of everything scanned, so the editor can
/// show the hit count as a proportion instead of a bare number.
#[derive(Clone, Copy, Debug, serde::Serialize, specta::Type)]
struct RuleHits {
    hits: u32,
    total: u32,
}

/// One event's stored columns, for the detail view. Reads the row the rules
/// were evaluated against instead of re-resolving the raw record with the
/// mapping currently in the editor.
#[tauri::command]
#[specta::specta]
async fn get_event(
    state: tauri::State<'_, AppState>,
    case_id: String,
    event_id: EventId,
) -> Result<Vec<FieldPreview>, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = state.store(&case_id)?;
        let fields = results::event_fields(&store, event_id.0).map_err(|e| e.to_string())?;
        Ok(fields
            .into_iter()
            .map(|(field, value)| FieldPreview {
                label: Field::from_key(&field)
                    .map_or_else(|| field.clone(), |f| f.label().to_owned()),
                field,
                value,
            })
            .collect())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Pages every event, rule or not. This is how an analyst inspects what the
/// rules did not catch.
#[tauri::command]
#[specta::specta]
async fn query_events(
    state: tauri::State<'_, AppState>,
    case_id: String,
    window: results::Window,
) -> Result<results::EventPage, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = state.store(&case_id)?;
        results::all_events(&store, &window).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// FR-6: drop a case and its database from disk. Irreversible, so the UI
/// confirms first; the id is validated inside `delete_case`.
#[tauri::command]
#[specta::specta]
async fn delete_case(state: tauri::State<'_, AppState>, case_id: String) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || delete_case_in(&state, &case_id))
        .await
        .map_err(|e| e.to_string())?
}

fn delete_case_in(state: &AppState, case_id: &str) -> Result<(), String> {
    state.stores.delete(case_id, || {
        state
            .cases_root
            .delete_case(case_id)
            .map_err(|e| e.to_string())
    })
}

/// Past cases, newest first. Reads `case.json` only so the list is cheap
/// even with many cases (docs/07).
#[tauri::command]
#[specta::specta]
async fn list_cases(state: tauri::State<'_, AppState>) -> Result<Vec<CaseSummary>, String> {
    let cases_root = state.cases_root.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut summaries = Vec::new();
        for case_id in cases_root.list_cases().map_err(|e| e.to_string())? {
            let Some(dir) = cases_root.case_dir(&case_id) else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(dir.join("case.json")) else {
                continue;
            };
            let json: serde_json::Value = match serde_json::from_str(&text) {
                Ok(json) => json,
                Err(_) => continue,
            };
            summaries.push(CaseSummary {
                case_id,
                input_dir: json["input_dir"].as_str().unwrap_or_default().to_string(),
                status: json["status"].as_str().unwrap_or("unknown").to_string(),
                event_count: json["event_count"].as_u64().unwrap_or(0) as u32,
            });
        }
        Ok(summaries)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// One row of the case list.
#[derive(Clone, serde::Serialize, specta::Type)]
struct CaseSummary {
    case_id: String,
    input_dir: String,
    status: String,
    event_count: u32,
}

/// Requests cooperative cancellation of the active parse, rule evaluation or draft count.
#[tauri::command]
#[specta::specta]
fn cancel_parse(state: tauri::State<'_, AppState>) {
    state.parse.cancel();
}

/// Resolves the portable cases root from env var, CLI flag, then the
/// executable's directory. Fails loudly instead of falling back to AppData.
fn resolve_root() -> Result<CasesRoot, String> {
    let env_dir = std::env::var_os("AWSLOG_CASES_DIR").map(PathBuf::from);
    let cli_dir = cli_cases_dir();
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate executable: {e}"))?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| "executable has no parent directory".to_string())?;

    let root = paths::resolve(&RootSources {
        env_dir: env_dir.as_deref(),
        cli_dir: cli_dir.as_deref(),
        exe_dir,
    });

    paths::prepare(&root).map_err(|e| {
        format!("{e}\nMove the app to a writable location, or set AWSLOG_CASES_DIR / --cases-dir.")
    })
}

/// Single flag; a full argument parser would be unjustified here.
fn cli_cases_dir() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let arg = arg.to_string_lossy().into_owned();
        if arg == "--cases-dir" {
            return args.next().map(PathBuf::from);
        }
        if let Some(value) = arg.strip_prefix("--cases-dir=") {
            return Some(PathBuf::from(value));
        }
    }
    None
}

/// Reports a startup failure and exits. A double-clicked `.exe` has no console,
/// so the message must reach the user through a native dialog (docs/07).
/// `AWSLOG_NO_DIALOG=1` keeps automated runs from blocking on it.
fn fatal(message: &str) -> ! {
    eprintln!("{message}");
    if std::env::var_os("AWSLOG_NO_DIALOG").is_none() {
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title("AWS Log Analyzer")
            .set_description(message)
            .set_buttons(rfd::MessageButtons::Ok)
            .show();
    }
    std::process::exit(1);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let root = match resolve_root() {
        Ok(root) => root,
        Err(message) => fatal(&message),
    };

    let log = Arc::new(match AppLog::open(&root) {
        Ok(log) => log,
        Err(e) => fatal(&format!(
            "cannot open app log in {}: {e}",
            root.path().display()
        )),
    });
    log.info(&format!("startup cases_root={}", root.path().display()));

    let webview_data = root.path().join("webview");

    let specta = Builder::<tauri::Wry>::new()
        .commands(collect_commands![
            cases_root,
            scan_directory,
            detect_logs,
            start_parse,
            cancel_parse,
            query_results,
            query_rule_matches,
            list_payload_keys,
            preview_head,
            get_raw_record,
            list_cases,
            delete_case,
            default_mapping,
            preview_mapping,
            list_rule_sources,
            evaluate_rule,
            save_rule,
            delete_rule,
            query_events,
            get_event,
            explain_rule,
            count_rule_matches
        ])
        .events(collect_events![DetectProgress, ParseProgress]);

    // Bindings are generated from the command signatures, so the TS types
    // cannot drift from Rust (AGENTS.md §3.4). Debug builds only.
    // Anchored to the manifest dir: output must not depend on the CWD.
    #[cfg(debug_assertions)]
    specta
        .export(
            specta_typescript::Typescript::default(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/../src/bindings.ts"),
        )
        .expect("failed to export TS bindings");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(specta.invoke_handler())
        .setup(move |app| {
            specta.mount_events(app);
            // Window is built here, not in tauri.conf.json: config windows are
            // created before setup, too late to redirect the webview data dir
            // away from AppData (docs/07-case-layout.md).
            // Clamped to the monitor's work area: `.center()` positions a
            // window but never shrinks one, so a fixed 1440x860 would hang
            // off the bottom of a 1366x768 laptop.
            let (width, height) = window_size(app);
            // Kept for the Windows run: the earlier clamp attempt failed
            // because the reported scale did not match the panel, and only a
            // log of the inputs makes that visible.
            #[cfg(debug_assertions)]
            match app.primary_monitor() {
                Ok(Some(m)) => eprintln!(
                    "monitor size={:?} scale={} work={:?} chosen={width}x{height}",
                    m.size(),
                    m.scale_factor(),
                    m.work_area().size
                ),
                _ => eprintln!("monitor unavailable chosen={width}x{height}"),
            }
            // Bundling is off (portable single exe), so nothing sets the
            // window/taskbar icon for us: embed it and apply it here.
            WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
                .title("AWS Log Analyzer")
                .inner_size(width, height)
                .min_inner_size(960.0, 640.0)
                .center()
                .icon(tauri::include_image!("icons/128x128.png"))?
                .data_directory(webview_data.clone())
                .build()?;
            #[cfg(debug_assertions)]
            if let Some(w) = app.get_webview_window("main") {
                eprintln!(
                    "window inner={:?} visible={:?} pos={:?}",
                    w.inner_size(),
                    w.is_visible(),
                    w.outer_position()
                );
            }

            app.manage(AppState {
                cases_root: root.clone(),
                parse: ParseSlot::default(),
                stores: Arc::new(StoreCache::default()),
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::{
        begin_rule_scan, count_rule_matches_in, default_mapping, delete_case_in, delete_rule_in,
        evaluate_rule_in, explain_rule, fit_window, paths, preview_mapping, query_results_in,
        results, save_rule_in, user_rule_path, write_user_rule, AppState, Arc, CasesRoot, Field,
        FieldPreview, MappingEntry, OffsetDateTime, ParseSlot, Path, PrimitiveDateTime, RuleHits,
        RuleSet, Store, StoreCache, MIN_WINDOW, SLOT_BUSY,
    };
    use std::sync::atomic::Ordering;

    #[test]
    fn a_second_parse_is_refused_while_one_runs() {
        let slot = ParseSlot::default();
        let first = slot.begin().expect("first run claims the slot");

        assert!(slot.begin().is_none(), "second run must be refused");

        // The refusal must not have replaced the live flag: cancelling still
        // reaches the run that is actually going.
        slot.cancel();
        assert!(first.flag.load(Ordering::Relaxed));
    }

    #[test]
    fn dropping_the_guard_frees_the_slot() {
        let slot = ParseSlot::default();
        let first = slot.begin().unwrap().flag.clone();
        // Guard from the line above is already dropped here.

        let second = slot.begin().expect("slot frees when the run ends");
        slot.cancel();

        // A finished run's flag must not be raised by the next run's cancel.
        assert!(second.flag.load(Ordering::Relaxed));
        assert!(!first.load(Ordering::Relaxed));
    }

    #[test]
    fn the_slot_frees_even_when_the_run_panics() {
        let slot = ParseSlot::default();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _run = slot.begin().expect("claims the slot");
            panic!("worker blew up");
        }));

        assert!(caught.is_err());
        // Without the Drop guard this would refuse every later parse.
        assert!(
            slot.begin().is_some(),
            "a panicking run must not lock the slot"
        );
    }

    #[test]
    fn an_override_changes_what_the_preview_resolves() {
        let record =
            r#"{"sourceIPAddress":"203.0.113.10","requestContext":{"clientIp":"198.51.100.7"}}"#;
        let overridden = vec![MappingEntry {
            field: "source_ip".to_owned(),
            label: Field::SourceIp.label().to_owned(),
            sources: vec!["requestContext.clientIp".to_owned()],
        }];

        let before = preview_mapping(record.to_owned(), vec![]).unwrap();
        let after = preview_mapping(record.to_owned(), overridden).unwrap();

        let ip = |rows: &[FieldPreview]| {
            rows.iter()
                .find(|r| r.field == "source_ip")
                .and_then(|r| r.value.clone())
        };
        assert_eq!(ip(&before).as_deref(), Some("203.0.113.10"));
        assert_eq!(ip(&after).as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn an_unknown_field_key_is_ignored_rather_than_breaking_the_mapping() {
        let entries = vec![MappingEntry {
            field: "not_a_column".to_owned(),
            label: "알 수 없음".to_owned(),
            sources: vec!["whatever".to_owned()],
        }];

        let rows = preview_mapping(r#"{"eventName":"ConsoleLogin"}"#.to_owned(), entries).unwrap();

        assert_eq!(rows.len(), Field::ALL.len());
        assert_eq!(
            rows.iter()
                .find(|r| r.field == "event_name")
                .and_then(|r| r.value.clone())
                .as_deref(),
            Some("ConsoleLogin")
        );
    }

    #[test]
    fn a_malformed_record_is_reported_not_panicked_on() {
        assert!(preview_mapping("{not json".to_owned(), vec![]).is_err());
    }

    #[test]
    fn a_broken_draft_is_explained_with_the_line_it_breaks_on() {
        let draft = "rule r {\n    fields:\n        $n = \"ConsoleLogin\"\n    condition:\n        event_name $n\n}";
        let problem = explain_rule(draft.to_owned()).unwrap_err();
        assert_eq!(problem.line, Some(3));
        assert!(
            problem.message.contains("expected a field name"),
            "{}",
            problem.message
        );

        // Two rules in one draft is a property of the draft, not a line.
        let two = "rule a { fields: $n = event_name exists condition: $n }\nrule b { fields: $n = event_name exists condition: $n }";
        assert_eq!(explain_rule(two.to_owned()).unwrap_err().line, None);
    }

    #[test]
    fn the_default_mapping_covers_every_column() {
        let rows = default_mapping();

        assert_eq!(rows.len(), Field::ALL.len());
        assert!(rows.iter().all(|r| !r.sources.is_empty()));
    }

    /// A parsed case with one event, so rule runs have something to match,
    /// and an app state over its root as the commands would see it.
    fn seeded_case() -> (tempfile::TempDir, AppState, String) {
        let tmp = tempfile::tempdir().unwrap();
        let root = paths::prepare(&tmp.path().join("cases")).unwrap();
        let id = seed_case(&root);
        let state = AppState {
            cases_root: root,
            parse: ParseSlot::default(),
            stores: Arc::new(StoreCache::default()),
        };
        (tmp, state, id)
    }

    fn seed_case(root: &CasesRoot) -> String {
        let case = root
            .create_case(Path::new("/logs/prod"), {
                let now = OffsetDateTime::now_utc();
                PrimitiveDateTime::new(now.date(), now.time())
            })
            .unwrap();
        let mut store = Store::create(&case.session_db(), case.id(), "/logs/prod").unwrap();
        store
            .register_file(0, "a.json.gz", 1, "cloudtrail")
            .unwrap();
        store
            .append_events(&[awslog_core::model::NormalizedEvent {
                file_id: 0,
                record_index: 0,
                event_time: None,
                event_source: Some("signin.amazonaws.com".into()),
                event_name: Some("ConsoleLogin".into()),
                aws_region: None,
                account_id: None,
                source_ip: None,
                user_agent: None,
                identity_type: Some("Root".into()),
                identity_arn: None,
                identity_name: None,
                mfa_authenticated: None,
                error_code: None,
                error_message: None,
                read_only: None,
                management_event: None,
                request: None,
                response: None,
                resources: None,
                raw: Some(r#"{"eventName":"ConsoleLogin"}"#.to_owned()),
            }])
            .unwrap();
        case.id().to_owned()
    }

    const HIT: &str = r#"rule my_hit {
        meta: description = "Console login" severity = "low"
        fields: $n = event_name == "ConsoleLogin"
        condition: $n
    }"#;

    /// Runs a rule the way `evaluate_rule` does: claim the shared slot, scan
    /// under that run's cancel flag, release when the scan returns.
    fn scan_rule(state: &AppState, case_id: &str, rule_id: &str) -> Result<u64, String> {
        let run = begin_rule_scan(&state.parse, || Ok(()))?;
        evaluate_rule_in(state, case_id, rule_id, run.cancelled())
    }

    /// The draft-count path, claimed the same way.
    fn count_draft(state: &AppState, case_id: &str, source: &str) -> Result<RuleHits, String> {
        let run = begin_rule_scan(&state.parse, || Ok(()))?;
        count_rule_matches_in(state, case_id, source, run.cancelled())
    }

    #[test]
    fn saving_a_rule_registers_it_pending_and_selecting_evaluates_it() {
        let (_tmp, state, case_id) = seeded_case();

        let rule_id = save_rule_in(&state, &case_id, HIT).unwrap();

        assert_eq!(rule_id, "my_hit");
        // One rule per file under cases/rules, named after its id, so delete
        // is a file delete.
        assert!(state
            .cases_root
            .user_rules_dir()
            .join("my_hit.yar")
            .is_file());
        let case_dir = state.cases_root.case_dir(&case_id).unwrap();
        // Snapshotted beside the case so the result stays explainable.
        assert!(case_dir.join("rules/user-my_hit.yar").is_file());
        let groups = state
            .store(&case_id)
            .unwrap()
            .rule_groups(&Default::default())
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rule_id, "my_hit");
        assert!(!groups[0].evaluated, "saving must not scan the case");

        let hits = scan_rule(&state, &case_id, "my_hit").unwrap();

        assert_eq!(hits, 1);
        let groups = state
            .store(&case_id)
            .unwrap()
            .rule_groups(&Default::default())
            .unwrap();
        assert!(groups[0].evaluated);
        assert_eq!(groups[0].match_count, 1);
    }

    #[test]
    fn an_older_case_shows_shipped_rule_names_from_the_current_pack() {
        // A case parsed before `rules.name` existed holds NULL names and a
        // snapshot without `meta: name`. The sidebar must still show names,
        // taken from the pack in this binary, without re-evaluating.
        let (_tmp, state, case_id) = seeded_case();
        {
            let store = state.store(&case_id).unwrap();
            let old_pack = RuleSet::from_source(
                r#"rule alb_server_error {
                       meta: description = "old" severity = "medium" log_type = "alb_access"
                       fields: $s = response.elb_status_code >= 500
                       condition: $s
                   }"#,
            )
            .unwrap();
            store
                .writer_handle()
                .unwrap()
                .begin_rule_run(old_pack.rules())
                .unwrap();
        }

        let page = query_results_in(
            &state,
            &case_id,
            &results::Window {
                log_type: Some("alb_access".to_owned()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(page.groups.len(), 1);
        assert_eq!(page.groups[0].rule_id, "alb_server_error");
        assert_eq!(page.groups[0].name, "서버 오류 (5xx)");
    }

    #[test]
    fn deleting_a_rule_removes_it_from_the_case_and_the_snapshot() {
        let (_tmp, state, case_id) = seeded_case();
        save_rule_in(&state, &case_id, HIT).unwrap();
        scan_rule(&state, &case_id, "my_hit").unwrap();

        delete_rule_in(&state, &case_id, "my_hit").unwrap();

        let case_dir = state.cases_root.case_dir(&case_id).unwrap();
        let store = state.store(&case_id).unwrap();
        assert!(store.rule_groups(&Default::default()).unwrap().is_empty());
        assert_eq!(store.matched_event_count(&Default::default()).unwrap(), 0);
        assert!(!state
            .cases_root
            .user_rules_dir()
            .join("my_hit.yar")
            .exists());
        // The snapshot must not keep claiming a deleted rule was applied.
        assert!(!case_dir.join("rules/user-my_hit.yar").exists());
    }

    #[test]
    fn a_rule_that_matches_nothing_is_recorded_with_zero_hits() {
        let (_tmp, state, case_id) = seeded_case();
        save_rule_in(
            &state,
            &case_id,
            r#"rule my_miss {
                meta: description = "Never" severity = "high"
                fields: $n = event_name == "DeleteTrail"
                condition: $n
            }"#,
        )
        .unwrap();

        let hits = scan_rule(&state, &case_id, "my_miss").unwrap();

        assert_eq!(hits, 0);
        let groups = state
            .store(&case_id)
            .unwrap()
            .rule_groups(&Default::default())
            .unwrap();
        // Listed, not dropped: an unexercised rule must be distinguishable
        // from one that was never loaded.
        assert_eq!(groups.len(), 1);
        assert!(groups[0].evaluated);
        assert_eq!(groups[0].match_count, 0);
    }

    /// Commands overlap (a results poll while a rule is saved), and each
    /// gets its own handle. Those handles must be connections to one
    /// database instance: a handle taken earlier sees a later write. Two
    /// independent opens of the file never would, and on Windows the second
    /// open is refused outright with a lock held by this very process.
    #[test]
    fn handles_on_one_case_share_a_single_database_instance() {
        let (_tmp, state, case_id) = seeded_case();
        let earlier = state.store(&case_id).unwrap();

        save_rule_in(&state, &case_id, HIT).unwrap();

        let groups = earlier.rule_groups(&Default::default()).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rule_id, "my_hit");
    }

    /// The cache keeps one idle case, but a command may still be running on
    /// a case the analyst has switched away from. Coming back to it must
    /// reuse the instance that command holds, not open a second one.
    #[test]
    fn returning_to_a_case_a_running_command_still_holds_reuses_its_instance() {
        let (_tmp, state, case_a) = seeded_case();
        let case_b = seed_case(&state.cases_root);
        let held = state.store(&case_a).unwrap();

        state.store(&case_b).unwrap();
        save_rule_in(&state, &case_a, HIT).unwrap();

        let groups = held.rule_groups(&Default::default()).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rule_id, "my_hit");
    }

    /// `remove_dir_all` would take `case.json` and `rules/` before failing
    /// on the locked database, leaving a case that is neither listed nor
    /// gone. While a command holds the case, deletion must not touch it.
    #[test]
    fn deleting_a_case_a_command_still_holds_is_refused_and_leaves_it_intact() {
        let (_tmp, state, case_id) = seeded_case();
        save_rule_in(&state, &case_id, HIT).unwrap();
        let case_dir = state.cases_root.case_dir(&case_id).unwrap();
        let held = state.store(&case_id).unwrap();

        assert!(delete_case_in(&state, &case_id).is_err());

        assert!(case_dir.join("session.duckdb").is_file());
        assert!(case_dir.join("rules/user-my_hit.yar").is_file());
        // Still usable through the held handle: nothing was pulled from under it.
        assert_eq!(held.rule_groups(&Default::default()).unwrap().len(), 1);
        drop(held);

        delete_case_in(&state, &case_id).unwrap();
        assert!(!case_dir.exists());
    }

    #[test]
    fn an_invalid_rule_never_reaches_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");

        assert!(write_user_rule(&rules, "rule broken {").is_err());
        // Two rules in one file would break delete-by-filename.
        assert!(write_user_rule(
            &rules,
            &format!("{HIT}\n{}", HIT.replace("my_hit", "other"))
        )
        .is_err());
        assert!(!rules.exists());
    }

    #[test]
    fn a_rule_id_cannot_escape_the_rules_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");

        assert!(user_rule_path(&rules, "../../etc/passwd").is_err());
        assert!(user_rule_path(&rules, "ok_name").is_ok());
    }

    #[test]
    fn rule_work_is_refused_while_a_parse_holds_the_slot() {
        let (_tmp, state, case_id) = seeded_case();
        save_rule_in(&state, &case_id, HIT).unwrap();
        let _parse = state.parse.begin().unwrap();

        // All three write or scan the same database, so they must not overlap.
        assert_eq!(
            scan_rule(&state, &case_id, "my_hit").unwrap_err(),
            SLOT_BUSY
        );
        assert_eq!(count_draft(&state, &case_id, HIT).unwrap_err(), SLOT_BUSY);
        assert!(save_rule_in(&state, &case_id, HIT).is_err());
    }

    /// Leaving the results view mid-evaluation: the rule must not be recorded
    /// as done, must keep no partial matches, and a later run must be whole.
    #[test]
    fn a_cancelled_rule_scan_stays_unevaluated_and_a_retry_starts_fresh() {
        let (_tmp, state, case_id) = seeded_case();
        save_rule_in(&state, &case_id, HIT).unwrap();

        let cancelled = {
            let run = begin_rule_scan(&state.parse, || Ok(())).unwrap();
            state.parse.cancel();
            evaluate_rule_in(&state, &case_id, "my_hit", run.cancelled())
        };

        assert!(cancelled.is_err(), "a cancelled scan must not report hits");
        let groups = state
            .store(&case_id)
            .unwrap()
            .rule_groups(&Default::default())
            .unwrap();
        assert!(!groups[0].evaluated, "an interrupted rule is not evaluated");
        assert_eq!(groups[0].match_count, 0, "partial hits must be discarded");

        assert_eq!(scan_rule(&state, &case_id, "my_hit").unwrap(), 1);
        let groups = state
            .store(&case_id)
            .unwrap()
            .rule_groups(&Default::default())
            .unwrap();
        assert!(groups[0].evaluated);
        assert_eq!(groups[0].match_count, 1);
    }

    /// The next parse may start only once the worker that held the slot is
    /// gone, and it must be able to start then.
    #[test]
    fn a_cancelled_scan_frees_the_slot_when_its_worker_exits() {
        let (_tmp, state, case_id) = seeded_case();
        save_rule_in(&state, &case_id, HIT).unwrap();
        let (entered, worker_entered) = std::sync::mpsc::channel();
        let (resume, worker_resume) = std::sync::mpsc::channel();

        let run = begin_rule_scan(&state.parse, || Ok(())).unwrap();
        let worker_state = state.clone();
        let worker = std::thread::spawn(move || {
            entered.send(()).unwrap();
            worker_resume.recv().unwrap();
            // The guard is owned here, so the slot is held until this returns.
            evaluate_rule_in(&worker_state, &case_id, "my_hit", run.cancelled())
        });

        worker_entered.recv().unwrap();
        state.parse.cancel();
        assert!(
            state.parse.begin().is_none(),
            "the slot stays claimed while the worker runs"
        );
        resume.send(()).unwrap();
        let outcome = worker.join().unwrap();

        assert!(outcome.is_err(), "the scan must report the cancellation");
        assert!(
            state.parse.begin().is_some(),
            "a new parse may start once the worker is gone"
        );
    }

    /// The UI cancels by calling `cancel_parse` when it leaves the results
    /// view. That cancel must not be able to fall between `invoke` and the
    /// scan registering, so the claim stands before `started` is signalled.
    #[test]
    fn the_start_signal_fires_only_after_the_slot_claim_stands() {
        let (_tmp, state, _case_id) = seeded_case();

        let run = begin_rule_scan(&state.parse, || {
            // What the frontend may do the instant it hears `started`.
            assert!(state.parse.begin().is_none(), "claim must already stand");
            state.parse.cancel();
            Ok(())
        })
        .unwrap();

        let cancelled = run.cancelled();
        assert!(
            cancelled(),
            "a cancel racing the signal must reach this run"
        );
    }

    #[test]
    fn a_scan_whose_start_signal_fails_holds_nothing() {
        let (_tmp, state, _case_id) = seeded_case();

        // A broken channel means the caller could never cancel this scan, so
        // it must not run at all.
        let refused = begin_rule_scan(&state.parse, || Err("채널이 끊어졌습니다".to_owned()));

        assert!(refused.is_err());
        assert!(state.parse.begin().is_some(), "the slot must be free again");
    }

    /// A draft count scans the case too, so it shares the slot and stops on
    /// the same cancel; closing the results view drops drafts as well.
    #[test]
    fn a_draft_count_shares_the_slot_and_stops_when_cancelled() {
        let (_tmp, state, case_id) = seeded_case();

        let cancelled = {
            let run = begin_rule_scan(&state.parse, || Ok(())).unwrap();
            state.parse.cancel();
            count_rule_matches_in(&state, &case_id, HIT, run.cancelled())
        };

        assert!(cancelled.is_err(), "a cancelled count must not report hits");
        let hits = count_draft(&state, &case_id, HIT).unwrap();
        assert_eq!((hits.hits, hits.total), (1, 1));
    }

    #[test]
    fn the_window_fits_the_screens_it_will_actually_run_on() {
        // Roomy: the preferred size is used as-is.
        assert_eq!(fit_window(1920.0, 1055.0), (1440.0, 900.0));
        // A 1366x768 laptop: both axes come down, height most of all.
        assert_eq!(fit_window(1366.0, 728.0), (1318.0, 680.0));
        // 1440x900 panel: height is the binding constraint.
        assert_eq!(fit_window(1440.0, 860.0), (1392.0, 812.0));
        // Never below the minimum, even on an absurdly small work area.
        assert_eq!(fit_window(800.0, 600.0), MIN_WINDOW);
        // Fits within the work area it was given, which is the whole point.
        for (w, h) in [(1366.0, 728.0), (1440.0, 860.0), (1920.0, 974.0)] {
            let (cw, ch) = fit_window(w, h);
            assert!(cw <= w && ch <= h, "{cw}x{ch} does not fit {w}x{h}");
        }
    }

    #[test]
    fn cancelling_with_no_run_is_a_no_op() {
        ParseSlot::default().cancel();
    }
}
