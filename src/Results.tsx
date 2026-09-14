import { useCallback, useEffect, useRef, useState } from "react";
import {
  commands,
  type FieldPreview,
  type MatchRow,
  type ResultPage,
  type RuleGroup,
  type RuleSource,
  type Window,
} from "./bindings";
import { RecordFields } from "./panels/RecordView";
import { RuleEditor } from "./panels/RuleEditor";
import { logTypeLabel } from "./lib/format";
import { useApp } from "./state";

const PAGE = 200;

/// Selection for the "every event" view. Not a rule id, so it can never
/// collide with one: rule ids are identifiers, this is not.
const ALL_EVENTS = "*";

/// The shapes the backend parses (`Store::bound`): a day, a minute or a
/// second in KST, with the obvious field ranges. Calendar validity (Feb 30)
/// is the backend's; a rejected bound is shown by the inputs.
const BOUND =
  /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])( ([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?)?$/;

/// The bound to send: the complete value, or "" while it is empty or still
/// being typed.
function boundOf(typed: string): string {
  const t = typed.trim();
  return BOUND.test(t) ? t : "";
}

function isBadBound(typed: string): boolean {
  const t = typed.trim();
  return t !== "" && !BOUND.test(t);
}

/** FR-6 results window: rule groups on the left, their matches on the right. */
export function Results({ caseId }: { caseId: string }) {
  const { reset, go, work } = useApp();
  const [page, setPage] = useState<ResultPage | null>(null);
  const [selected, setSelected] = useState<string>(ALL_EVENTS);
  // One `files.log_type`, or null for the whole case. Scopes the rule list,
  // the counts and the event list alike.
  const [logType, setLogType] = useState<string | null>(null);
  // KST bounds typed as text: `YYYY-MM-DD`, `YYYY-MM-DD HH:MM` or
  // `YYYY-MM-DD HH:MM:SS`, both inclusive at their unit; "" is open. Ranks
  // above the rule selection: every count and list is inside this range.
  // The typed value settles before it queries, and only a complete bound is
  // sent — a half-typed one is neither a filter nor an error.
  const [fromTyped, setFromTyped] = useState("");
  const [toTyped, setToTyped] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => {
      setFrom(boundOf(fromTyped));
      setTo(boundOf(toTyped));
    }, 300);
    return () => clearTimeout(timer);
  }, [fromTyped, toTyped]);
  // Everything the backend narrows on, apart from paging and search.
  const scope = { log_type: logType, from: from || null, to: to || null };
  const pageWindow = (
    offset: number,
    search: string,
    newestFirst: boolean,
  ): Window => ({
    offset,
    limit: PAGE,
    search,
    newest_first: newestFirst,
    ...scope,
  });
  // Every effective rule's text, shipped or user, so any of them can be
  // opened in the editor. Saving writes a user override either way.
  const [sources, setSources] = useState<Record<string, RuleSource>>({});
  const [editing, setEditing] = useState<{ ruleId: string | null } | null>(
    null,
  );
  // Destructive action is confirmed in the row it affects. A global minus
  // button made it too easy to delete whichever rule happened to be selected.
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  // A rule being evaluated over the case right now. It opens the same
  // database read-write; paging meanwhile risks a DuckDB lock error, and a
  // second evaluation would be refused by the backend, so the list holds.
  const [evaluating, setEvaluating] = useState<string | null>(null);
  const reevaluating = evaluating !== null;
  // The rule whose evaluation failed, with the reason. Held so the effect
  // does not retry on its own: clearing `evaluating` alone re-ran it in a
  // loop against a persistent backend error. Clicking the rule retries.
  const [failed, setFailed] = useState<{
    ruleId: string;
    error: string;
  } | null>(null);
  // Discards a response from a rule the user already moved off.
  const generation = useRef(0);
  const [matches, setMatches] = useState<MatchRow[]>([]);
  const [total, setTotal] = useState(0);
  // True between issuing the first page and its arrival, so an empty list
  // is not announced as "0건" while the query is still running.
  const [rowsLoading, setRowsLoading] = useState(true);
  // What the user typed, and the debounced value the queries actually use: a
  // keystroke must not cost a full-table scan.
  const [typed, setTyped] = useState("");
  const [search, setSearch] = useState("");
  // Oldest first: an incident is read forwards in time.
  const [newestFirst, setNewestFirst] = useState(false);
  const [raw, setRaw] = useState<{
    eventId: number;
    body: string;
    fields: FieldPreview[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  // A bound the backend rejected (`Store::bound`, e.g. hour 25). Shown by
  // the inputs instead of replacing the screen, so it can be corrected.
  const [filterError, setFilterError] = useState<string | null>(null);
  function fail(message: string) {
    if (message.startsWith("invalid date/time")) return setFilterError(message);
    setError(message);
  }

  // `reload` re-reads groups and totals; saving or deleting a rule changes
  // them, so it is not a mount-only effect.
  const [version, setVersion] = useState(0);
  useEffect(() => {
    // Unlike the row queries, this one had no staleness guard: a slow
    // response from the previous tab would overwrite the current tab's
    // groups and could reset a valid selection.
    let stale = false;
    // No search here: the sidebar counts describe each rule, not the filter.
    commands.queryResults(caseId, null, pageWindow(0, "", false)).then((r) => {
      if (stale) return;
      if (r.status === "error") return fail(r.error);
      setFilterError(null);
      setPage(r.data);
      // The evaluation this reload was waiting for is visible now.
      setEvaluating((id) =>
        id && r.data.groups.some((g) => g.rule_id === id && !g.evaluated)
          ? id
          : null,
      );
      // A rule scoped to another type is not in this tab's list; keeping
      // it selected would show a list the sidebar does not name.
      setSelected((s) =>
        s === ALL_EVENTS || r.data.groups.some((g) => g.rule_id === s)
          ? s
          : ALL_EVENTS,
      );
    });
    return () => {
      stale = true;
    };
  }, [caseId, version, logType, from, to]);

  // A full-text scan per keystroke would stall on a large case, so the typed
  // value settles first.
  useEffect(() => {
    const timer = setTimeout(() => setSearch(typed.trim()), 250);
    return () => clearTimeout(timer);
  }, [typed]);

  // Which rules exist and what they say; a save or delete changes both.
  useEffect(() => {
    commands.listRuleSources().then((r) => {
      if (r.status === "ok") {
        setSources(Object.fromEntries(r.data.map((u) => [u.rule_id, u])));
      }
    });
  }, [version]);

  // Rules are evaluated when first opened (docs/04 lazy evaluation): the
  // parse only registers them. Selecting a pending rule runs it once and
  // reloads the page so its count and matches appear.
  useEffect(() => {
    if (!page || selected === ALL_EVENTS || evaluating) return;
    if (failed?.ruleId === selected) return;
    const group = page.groups.find((g) => g.rule_id === selected);
    if (!group || group.evaluated) return;
    setEvaluating(selected);
    commands.evaluateRule(caseId, selected).then((r) => {
      if (r.status === "error") {
        setFailed({ ruleId: selected, error: r.error });
        setEvaluating(null);
        return;
      }
      // `evaluating` clears when the reloaded page lands (sidebar effect):
      // clearing it here, with the stale page still showing the rule as
      // pending, would start the same evaluation a second time.
      setVersion((v) => v + 1);
    });
  }, [page, selected, evaluating, failed, caseId]);

  useEffect(() => {
    setMatches([]);
    setRowsLoading(true);
    const run = ++generation.current;
    if (selected === ALL_EVENTS) {
      commands
        .queryEvents(caseId, pageWindow(0, search, newestFirst))
        .then((r) => {
          if (run !== generation.current) return;
          setRowsLoading(false);
          if (r.status === "error") return fail(r.error);
          setFilterError(null);
          setMatches(r.data.rows);
          setTotal(r.data.total);
        });
      return;
    }
    commands
      .queryResults(caseId, selected, pageWindow(0, search, newestFirst))
      .then((r) => {
        if (run !== generation.current) return;
        setRowsLoading(false);
        if (r.status === "error") return fail(r.error);
        setFilterError(null);
        setMatches(r.data.matches);
        setTotal(r.data.total_matches);
      });
  }, [caseId, selected, version, search, newestFirst, logType, from, to]);

  // Paging, not one huge payload: the backend caps each page at 1000 rows.
  // The in-flight guard matters: the virtualizer fires this on every render
  // near the end, and two overlapping fetches would append the same page.
  // Both views now report a filtered total, so this is the length of the
  // list on screen rather than the case's event count.
  const shownTotal = total;

  const loading = useRef(false);
  const loadMore = useCallback(async () => {
    // Guarded on the closure's own values. The previous version probed the
    // length through a setState updater, which React does not always run
    // eagerly — when it did not, paging stopped after the first page.
    const offset = matches.length;
    if (loading.current || reevaluating || offset >= shownTotal) return;
    const run = generation.current;
    loading.current = true;
    try {
      const rows =
        selected === ALL_EVENTS
          ? await commands.queryEvents(
              caseId,
              pageWindow(offset, search, newestFirst),
            )
          : await commands.queryResults(
              caseId,
              selected,
              pageWindow(offset, search, newestFirst),
            );
      // A page that arrived after the user switched rules, searched or
      // reversed the order belongs to the previous list; appending it would
      // interleave two different queries.
      if (run !== generation.current) return;
      if (rows.status === "error") return fail(rows.error);
      const next = "rows" in rows.data ? rows.data.rows : rows.data.matches;
      // Offset was captured before the await; ignore a stale response.
      setMatches((prev) =>
        prev.length === offset ? [...prev, ...next] : prev,
      );
    } finally {
      loading.current = false;
    }
  }, [
    caseId,
    selected,
    shownTotal,
    matches.length,
    reevaluating,
    search,
    newestFirst,
    logType,
    from,
    to,
  ]);

  // Focus moves into the dialog when it opens, so the keyboard is not left
  // behind on the list underneath (aria-modal focus requirement).
  const closeRaw = useRef<HTMLButtonElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (raw) {
      closeRaw.current?.focus();
      return;
    }
    // Closing returns the keyboard where it came from, so the next row is one
    // Tab away instead of back at the top of the document.
    opener.current?.focus();
    opener.current = null;
  }, [raw]);

  // Esc closes the raw drawer; a modal without a keyboard exit traps focus.
  useEffect(() => {
    if (!raw) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setRaw(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [raw]);

  async function removeRule(ruleId: string) {
    const r = await commands.deleteRule(caseId, ruleId);
    setConfirmDelete(null);
    if (r.status === "error") return setError(r.error);
    setSelected(ALL_EVENTS);
    setVersion((v) => v + 1);
  }

  /// The detail view resolves the record through the same mapping the parse
  /// used, so the drawer names the fields exactly as the columns do.
  async function showRaw(eventId: number, from?: HTMLElement) {
    opener.current = from ?? null;
    const r = await commands.getRawRecord(caseId, eventId);
    if (r.status === "error") return setError(r.error);
    let body = "(원본이 저장되지 않음)";
    if (r.data) {
      try {
        body = JSON.stringify(JSON.parse(r.data), null, 2);
      } catch {
        body = r.data;
      }
    }
    // Stored columns, not the raw record re-resolved: this case was parsed
    // with its own mapping (snapshotted in the case), and the editor's
    // mapping belongs to the next run.
    const stored = await commands.getEvent(caseId, eventId);
    const fields = stored.status === "ok" ? stored.data : [];
    setRaw({ eventId, body, fields });
  }

  if (error) return <p className="error">{error}</p>;
  if (!page) return <p>결과 불러오는 중…</p>;

  return (
    <section className="results">
      <header>
        <h1>분석 결과</h1>
        <code>{caseId}</code>
        <span className="grow" />
        {/* Plain navigation always works; `reset` refuses while a parse
            runs, which would otherwise strand the user on this screen. */}
        <button onClick={() => go("start")}>시작 화면</button>
        <button
          onClick={reset}
          disabled={work !== "idle"}
          title={work === "idle" ? undefined : "파싱이 끝난 뒤에 가능합니다"}
        >
          새 로그 가져오기
        </button>
      </header>

      {/* Types come from the case, so a new parser adds its own tab. */}
      {page.log_types.length > 0 && (
        <nav className="log-tabs" role="tablist" aria-label="로그 타입">
          <button
            role="tab"
            aria-selected={logType === null}
            className={logType === null ? "active" : ""}
            onClick={() => setLogType(null)}
          >
            전체
            <span>
              {page.log_types
                .reduce((sum, t) => sum + t.events, 0)
                .toLocaleString()}
            </span>
          </button>
          {page.log_types.map((t) => (
            <button
              key={t.log_type}
              role="tab"
              aria-selected={logType === t.log_type}
              className={logType === t.log_type ? "active" : ""}
              onClick={() => setLogType(t.log_type)}
            >
              {logTypeLabel(t.log_type)}
              <span>{t.events.toLocaleString()}</span>
            </button>
          ))}
        </nav>
      )}

      <div className="results-body">
        <div className="rule-pane">
          {/* Above the rules on purpose: the range narrows what the rules
              count, so it reads as the outer filter. */}
          <div className="date-filter" role="group" aria-label="기간 필터">
            <label>
              <span>부터</span>
              <input
                type="text"
                inputMode="numeric"
                placeholder="YYYY-MM-DD HH:MM:SS"
                value={fromTyped}
                aria-invalid={isBadBound(fromTyped)}
                className={isBadBound(fromTyped) ? "invalid" : ""}
                onChange={(e) => setFromTyped(e.target.value)}
              />
            </label>
            <label>
              <span>까지</span>
              <input
                type="text"
                inputMode="numeric"
                placeholder="YYYY-MM-DD HH:MM:SS"
                value={toTyped}
                aria-invalid={isBadBound(toTyped)}
                className={isBadBound(toTyped) ? "invalid" : ""}
                onChange={(e) => setToTyped(e.target.value)}
              />
            </label>
            <button
              className="linklike"
              disabled={!fromTyped && !toTyped}
              onClick={() => {
                setFromTyped("");
                setToTyped("");
              }}
            >
              초기화
            </button>
            {page.first_day && page.last_day && (
              <span className="date-span">
                {`${page.first_day} ~ ${page.last_day}`}
              </span>
            )}
            {filterError && (
              <span className="date-error" role="alert">
                {filterError}
              </span>
            )}
          </div>
          <header>
            <div className="rule-heading">
              <h2>탐지 룰</h2>
              <span>기본 룰과 사용자 룰</span>
            </div>
            <span className="grow" />
            <span className="rule-total">{page.groups.length}개</span>
            <button
              className="add-rule"
              aria-label="룰 추가"
              title="새 탐지 룰 추가"
              onClick={() => setEditing({ ruleId: null })}
            >
              <span aria-hidden="true">+</span>새 룰
            </button>
          </header>

          <ul className="rule-list">
            {/* Every event, rule or not: the list of rules alone cannot show
                what the rules missed. */}
            <li className={selected === ALL_EVENTS ? "active" : ""}>
              <button
                className="rule-select all-events"
                onClick={() => {
                  setConfirmDelete(null);
                  setSelected(ALL_EVENTS);
                }}
              >
                <span className="rule-label">
                  <span className="rule-marker overview" aria-hidden="true" />
                  <span className="rule-id">전체 이벤트</span>
                </span>
                <span className="hits">
                  {page.total_events.toLocaleString()}건
                </span>
              </button>
            </li>
            {page.groups.map((group) => (
              <RuleItem
                key={group.rule_id}
                group={group}
                active={group.rule_id === selected}
                user={sources[group.rule_id]?.user ?? false}
                evaluating={evaluating === group.rule_id}
                failed={failed?.ruleId === group.rule_id}
                confirmingDelete={confirmDelete === group.rule_id}
                busy={reevaluating}
                onSelect={() => {
                  setConfirmDelete(null);
                  // A click is the explicit retry after a failed evaluation.
                  setFailed((f) => (f?.ruleId === group.rule_id ? null : f));
                  setSelected(group.rule_id);
                }}
                onEdit={() => {
                  setConfirmDelete(null);
                  setEditing({ ruleId: group.rule_id });
                }}
                onAskDelete={() => {
                  setSelected(group.rule_id);
                  setConfirmDelete(group.rule_id);
                }}
                onCancelDelete={() => setConfirmDelete(null)}
                onDelete={() => void removeRule(group.rule_id)}
              />
            ))}
          </ul>
          {failed && (
            <p className="error small rule-error" role="alert">
              {failed.ruleId} 평가 실패: {failed.error} — 룰을 다시 클릭하면
              재시도합니다.
            </p>
          )}
        </div>
        <MatchList
          matches={matches}
          total={shownTotal}
          rowHeight={ROW_HEIGHT}
          search={typed}
          onSearch={setTyped}
          searchLabel={
            selected === ALL_EVENTS
              ? "전체 이벤트에서 검색"
              : `${selected} 결과에서 검색`
          }
          newestFirst={newestFirst}
          onToggleSort={() => setNewestFirst((v) => !v)}
          // A new list under the same scrollbar: the old offset would land on
          // an unrelated row, or past the end of a shorter filtered list.
          viewKey={`${selected}\u0000${search}\u0000${newestFirst}\u0000${logType}\u0000${from}\u0000${to}`}
          evaluating={evaluating === selected}
          loading={rowsLoading}
          layout={layoutFor(logType, page.log_types)}
          onLoadMore={loadMore}
          onShowRaw={showRaw}
        />
      </div>

      {editing && (
        <RuleEditor
          caseId={caseId}
          initial={
            editing.ruleId ? (sources[editing.ruleId]?.source ?? "") : ""
          }
          onClose={() => setEditing(null)}
          onSave={async (source) => {
            const r = await commands.saveRule(caseId, source);
            if (r.status === "error") return r.error;
            // Selecting the saved rule evaluates it (see the effect above).
            setSelected(r.data);
            setVersion((v) => v + 1);
            return null;
          }}
        />
      )}

      {/* A drawer, not a floating card: the old one covered the last rows of
          the list it was opened from. The backdrop takes the click and Esc
          closes it, so there is always a way out. */}
      {raw && (
        <div
          className="raw-backdrop"
          role="presentation"
          onClick={() => setRaw(null)}
        >
          <aside
            className="raw"
            role="dialog"
            aria-modal="true"
            aria-label={`원본 레코드 ${raw.eventId}`}
            onClick={(e) => e.stopPropagation()}
          >
            <header>
              <h2>이벤트 상세 #{raw.eventId}</h2>
              <span className="grow" />
              <button ref={closeRaw} onClick={() => setRaw(null)}>
                닫기
              </button>
            </header>
            {raw.fields.length > 0 ? (
              <RecordFields preview={raw.fields} />
            ) : (
              <p className="muted small">원본이 저장되지 않았습니다.</p>
            )}
            {/* The raw record stays available but folded: it is the fallback
                for anything the mapping does not name. */}
            <details className="raw-json">
              <summary>원본 JSON</summary>
              <pre>{raw.body}</pre>
            </details>
          </aside>
        </div>
      )}
    </section>
  );
}

function RuleItem({
  group,
  active,
  user,
  evaluating,
  failed,
  confirmingDelete,
  busy,
  onSelect,
  onEdit,
  onAskDelete,
  onCancelDelete,
  onDelete,
}: {
  group: RuleGroup;
  active: boolean;
  /// From `cases/rules/`: deleting removes the file. A shipped rule is only
  /// removed from this case.
  user: boolean;
  evaluating: boolean;
  failed: boolean;
  confirmingDelete: boolean;
  busy: boolean;
  onSelect: () => void;
  onEdit: () => void;
  onAskDelete: () => void;
  onCancelDelete: () => void;
  onDelete: () => void;
}) {
  return (
    <li className={active ? "active" : ""}>
      <button
        className="rule-select"
        onClick={onSelect}
        title={user ? group.description : `기본 제공 룰 · ${group.description}`}
      >
        <span className="rule-label">
          <span
            className={`rule-marker severity-${group.severity}`}
            aria-hidden="true"
          />
          <span className="rule-id">{group.rule_id}</span>
        </span>
        {/* No count on the row: the list under the table carries it. */}
        {evaluating ? (
          <span
            className="rule-spinner"
            role="status"
            aria-label={`${group.rule_id} 평가 중`}
          />
        ) : failed ? (
          <span className="hits pending failed">실패 · 재시도</span>
        ) : null}
      </button>
      {
        <div
          className={`rule-actions${confirmingDelete ? " confirming" : ""}`}
          aria-busy={busy}
        >
          {confirmingDelete ? (
            <>
              <button
                className="cancel"
                aria-label={`${group.rule_id} 삭제 취소`}
                title="삭제 취소"
                onClick={onCancelDelete}
                disabled={busy}
              >
                <RuleActionIcon name="cancel" />
              </button>
              <button
                className="danger"
                aria-label={`${group.rule_id} 삭제 확인`}
                title={busy ? "삭제 중" : "삭제 확인"}
                onClick={onDelete}
                disabled={busy}
              >
                <RuleActionIcon name="delete" />
              </button>
            </>
          ) : (
            <>
              <button
                className="edit"
                aria-label={`${group.rule_id} 수정`}
                title="룰 수정"
                onClick={onEdit}
                disabled={busy}
              >
                <RuleActionIcon name="edit" />
              </button>
              <button
                className="delete"
                aria-label={`${group.rule_id} 삭제`}
                title={user ? "룰 삭제" : "이 케이스에서 룰 제거"}
                onClick={onAskDelete}
                disabled={busy}
              >
                <RuleActionIcon name="delete" />
              </button>
            </>
          )}
        </div>
      }
    </li>
  );
}

/// Small line icons keep the row compact; the surrounding button owns the
/// accessible label, so the SVG itself stays out of the accessibility tree.
function RuleActionIcon({ name }: { name: "edit" | "delete" | "cancel" }) {
  if (name === "edit") {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 20h9" />
        <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z" />
      </svg>
    );
  }
  if (name === "cancel") {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="m6 6 12 12M18 6 6 18" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5" />
    </svg>
  );
}

/// Windowed by hand: only the rows in view are in the DOM, and the scroll
/// position drives both the window and paging.
///
/// This replaced @tanstack/react-virtual, which was not at fault — the
/// "frozen window" seen while testing was the headless harness not emitting
/// scroll events for programmatic `scrollTop` assignment. The rows are a
/// fixed height, so the arithmetic here is a few lines and one dependency
/// less; do not read this as the library being broken.
const ROW_HEIGHT = 48;
const OVERSCAN = 12;

type EventTone = "read" | "change" | "danger" | "identity";

/// Column set for the match list. ALB rows are HTTP requests and read as
/// method/status/URL; CloudTrail rows are API calls and read as
/// event/service/principal. A mixed list falls back to the CloudTrail set,
/// which every row can fill.
type Layout = "http" | "waf" | "cloudtrail";

function layoutFor(
  tab: string | null,
  present: { log_type: string }[],
): Layout {
  const only = tab ?? (present.length === 1 ? present[0].log_type : null);
  switch (only) {
    case "alb_access":
    case "apigw_access":
    case "nginx_access":
      return "http";
    case "waf_acl":
      return "waf";
    default:
      return "cloudtrail";
  }
}

/// An ARN read as its resource part: `arn:aws:s3:::bucket/key` → `bucket/key`.
/// The service is already its own column.
function resourceLabel(arn: string | null): string {
  if (!arn) return "—";
  const parts = arn.split(":");
  return parts.length >= 6 ? parts.slice(5).join(":") : arn;
}

function wafTone(action: string | null): string {
  if (action === "BLOCK") return "status-5xx";
  if (action === "COUNT" || action === "CAPTCHA" || action === "CHALLENGE")
    return "status-3xx";
  return action ? "status-2xx" : "";
}

function statusTone(status: string | null): string {
  const code = Number(status);
  if (!status || Number.isNaN(code)) return "";
  if (code >= 500) return "status-5xx";
  if (code >= 400) return "status-4xx";
  if (code >= 300) return "status-3xx";
  return "status-2xx";
}

function eventTone(name: string | null): EventTone {
  if (!name) return "read";
  if (
    /^(?:Delete|Terminate|Remove|Detach|Revoke|Stop|Disable|Deregister)/.test(
      name,
    )
  ) {
    return "danger";
  }
  if (
    /^(?:Create|Put|Update|Attach|Authorize|Start|Run|Modify|Set|Enable|Add|Register)/.test(
      name,
    )
  ) {
    return "change";
  }
  if (
    /(?:Login|AssumeRole|Federat|Authenticate|Credential|Token|Password|Policy)/i.test(
      name,
    )
  ) {
    return "identity";
  }
  return "read";
}

function serviceLabel(source: string | null): string {
  if (!source) return "—";
  const service = source.split(".")[0];
  return service === "signin" ? "IAM" : service.toUpperCase();
}

function principalSummary(arn: string | null): {
  kind: "ROLE" | "USER" | "ROOT" | "ARN" | null;
  label: string;
} {
  if (!arn) return { kind: null, label: "—" };
  const assumedRole = arn.match(/:assumed-role\/([^/]+)\/(.+)$/);
  if (assumedRole) {
    return { kind: "ROLE", label: `${assumedRole[1]} / ${assumedRole[2]}` };
  }
  const user = arn.match(/:user\/(.+)$/);
  if (user) return { kind: "USER", label: user[1] };
  if (arn.endsWith(":root")) return { kind: "ROOT", label: "Root account" };
  return { kind: "ARN", label: arn.slice(arn.lastIndexOf("/") + 1) || arn };
}

function endpointKind(value: string | null): "IP" | "HOST" | null {
  if (!value) return null;
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(":")
    ? "IP"
    : "HOST";
}

function MatchList({
  matches,
  total,
  rowHeight,
  search,
  onSearch,
  searchLabel,
  newestFirst,
  onToggleSort,
  viewKey,
  evaluating,
  loading,
  layout,
  onLoadMore,
  onShowRaw,
}: {
  matches: MatchRow[];
  total: number;
  /// One value feeds the container height, the window maths and each row's
  /// offset; passing it in keeps them from drifting apart.
  rowHeight: number;
  /// The raw text, so the field shows every keystroke while the query behind
  /// it waits for the debounce.
  search: string;
  onSearch: (text: string) => void;
  /// Names what is being searched — the selected rule's matches, not the case.
  searchLabel: string;
  newestFirst: boolean;
  onToggleSort: () => void;
  /// Changes whenever the rows underneath are a different list.
  viewKey: string;
  /// The selected rule is being run over the case; the rows are on the way.
  evaluating: boolean;
  /// First page still in flight.
  loading: boolean;
  /// Which column set the rows use (see `layoutFor`).
  layout: Layout;
  onLoadMore: () => void;
  onShowRaw: (eventId: number, from?: HTMLElement) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(600);

  // A row height change invalidates the scroll position, and so does a new
  // list: the same offset would land on a different row, or past the end.
  useEffect(() => {
    parentRef.current?.scrollTo({ top: 0 });
    setScrollTop(0);
  }, [rowHeight, viewKey]);

  useEffect(() => {
    const el = parentRef.current;
    if (!el) return;
    setViewport(el.clientHeight);
    const observer = new ResizeObserver(() => setViewport(el.clientHeight));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
  const end = Math.min(
    matches.length,
    Math.ceil((scrollTop + viewport) / rowHeight) + OVERSCAN,
  );
  const visible = matches.slice(start, end);

  return (
    <div className="match-pane">
      <div className="match-head">
        <input
          className="match-search"
          type="search"
          value={search}
          placeholder={searchLabel}
          aria-label={searchLabel}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => onSearch(e.target.value)}
        />
        <span className="match-count">
          <strong>{matches.length.toLocaleString()}</strong> /{" "}
          {total.toLocaleString()} 건 표시
        </span>
        {/* One button, not a dropdown: there are exactly two orders, and the
            label states the order the list is in. */}
        <button
          className="sort-toggle"
          onClick={onToggleSort}
          aria-pressed={newestFirst}
          title="시각 정렬 바꾸기"
        >
          {newestFirst ? "최신순 ↓" : "오래된순 ↑"}
        </button>
      </div>
      <div className={`match-cols cols-${layout}`} role="presentation">
        {layout === "http" ? (
          <>
            <span>시각 (KST)</span>
            <span>메서드</span>
            <span>상태</span>
            <span>요청 URL</span>
            <span>출발지 IP</span>
            <span>대상</span>
            <span>User-Agent</span>
          </>
        ) : layout === "waf" ? (
          <>
            <span>시각 (KST)</span>
            <span>조치</span>
            <span>메서드</span>
            <span>요청 URL</span>
            <span>출발지 IP</span>
            <span>국가</span>
            <span>종료 룰</span>
            <span>User-Agent</span>
          </>
        ) : (
          <>
            <span>시각 (KST)</span>
            <span>이벤트</span>
            <span>서비스</span>
            <span>주체</span>
            <span>출발지 IP</span>
            <span>리전</span>
            <span>오류</span>
            <span>리소스</span>
          </>
        )}
      </div>
      <div
        ref={parentRef}
        className="match-scroll"
        onScroll={(e) => {
          const el = e.currentTarget;
          setScrollTop(el.scrollTop);
          // Fetch before the user reaches the end, so scrolling never stalls.
          if (
            el.scrollHeight - el.scrollTop - el.clientHeight <
            rowHeight * 8
          ) {
            onLoadMore();
          }
        }}
      >
        {/* Nothing to list, and nothing on the way: say so rather than
            leave an empty pane that could be a slow query. */}
        {!evaluating && !loading && matches.length === 0 && (
          <div className="match-empty" role="status">
            <svg
              viewBox="0 0 48 48"
              width="44"
              height="44"
              aria-hidden="true"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M8 18l16-8 16 8-16 8-16-8z" />
              <path d="M8 18v12l16 8 16-8V18" />
              <path d="M24 26v12" />
            </svg>
            <strong>0건</strong>
            <span>
              {search
                ? "검색 조건에 맞는 데이터가 없습니다."
                : "표시할 데이터가 없습니다."}
            </span>
          </div>
        )}
        {/* An empty pane while the rule runs read as "no matches". */}
        {evaluating && matches.length === 0 && (
          <div className="match-loading" role="status" aria-live="polite">
            <span className="rule-spinner" aria-hidden="true" />
            <strong>룰을 평가하는 중입니다</strong>
            <span>
              저장된 이벤트를 훑고 있습니다. 매치가 나오면 여기에 표시됩니다.
            </span>
          </div>
        )}
        <div
          style={{ height: matches.length * rowHeight, position: "relative" }}
        >
          {visible.map((row, i) => {
            const principal = principalSummary(row.identity_arn);
            const endpoint = endpointKind(row.source_ip);
            return (
              <div
                key={row.event_id}
                className="match-row"
                role="button"
                tabIndex={0}
                aria-label={`${row.event_time ?? ""} ${row.event_name ?? ""} 상세 보기`}
                onClick={(e) => {
                  if (row.event_id !== null)
                    onShowRaw(row.event_id, e.currentTarget);
                }}
                onKeyDown={(e) => {
                  if (
                    (e.key === "Enter" || e.key === " ") &&
                    row.event_id !== null
                  ) {
                    e.preventDefault();
                    onShowRaw(row.event_id, e.currentTarget);
                  }
                }}
                style={{
                  position: "absolute",
                  top: (start + i) * rowHeight,
                  left: 0,
                  width: "100%",
                  height: rowHeight,
                }}
              >
                <div className={`match-main cols-${layout}`}>
                  <code className="m-time">{row.event_time ?? "—"}</code>
                  {layout === "http" ? (
                    <>
                      <span
                        className={`event-badge event-${eventTone(row.event_name)}`}
                        title={row.event_name ?? undefined}
                      >
                        {row.event_name ?? "—"}
                      </span>
                      <span
                        className={`status-badge ${statusTone(row.status)}`}
                      >
                        {row.status ?? "—"}
                      </span>
                      <span className="url" title={row.url ?? undefined}>
                        {row.url ?? "—"}
                      </span>
                      <span
                        className="endpoint"
                        title={row.source_ip ?? undefined}
                      >
                        {endpoint && <small>{endpoint}</small>}
                        <span>{row.source_ip ?? "—"}</span>
                      </span>
                      <span
                        className="endpoint"
                        title={row.target ?? undefined}
                      >
                        <span>{row.target ?? "—"}</span>
                      </span>
                      <span className="url" title={row.user_agent ?? undefined}>
                        {row.user_agent ?? "—"}
                      </span>
                    </>
                  ) : layout === "waf" ? (
                    <>
                      <span
                        className={`status-badge ${wafTone(row.event_name)}`}
                        title={row.event_name ?? undefined}
                      >
                        {row.event_name ?? "—"}
                      </span>
                      <span className="event-badge event-read">
                        {row.method ?? "—"}
                      </span>
                      <span className="url" title={row.url ?? undefined}>
                        {row.url ?? "—"}
                      </span>
                      <span
                        className="endpoint"
                        title={row.source_ip ?? undefined}
                      >
                        {endpoint && <small>{endpoint}</small>}
                        <span>{row.source_ip ?? "—"}</span>
                      </span>
                      <span className="region">{row.country ?? "—"}</span>
                      <span className="url" title={row.rule ?? undefined}>
                        {row.rule ?? "—"}
                      </span>
                      <span className="url" title={row.user_agent ?? undefined}>
                        {row.user_agent ?? "—"}
                      </span>
                    </>
                  ) : (
                    <>
                      <span
                        className={`event-badge event-${eventTone(row.event_name)}`}
                        title={row.event_name ?? undefined}
                      >
                        {row.event_name ?? "—"}
                      </span>
                      <span
                        className="service-badge"
                        title={row.event_source ?? undefined}
                      >
                        {serviceLabel(row.event_source)}
                      </span>
                      <span
                        className="principal"
                        title={row.identity_arn ?? undefined}
                      >
                        {principal.kind && <small>{principal.kind}</small>}
                        <span>{principal.label}</span>
                      </span>
                      <span
                        className="endpoint"
                        title={row.source_ip ?? undefined}
                      >
                        {endpoint && <small>{endpoint}</small>}
                        <span>{row.source_ip ?? "—"}</span>
                      </span>
                      <span className="region">{row.aws_region ?? "—"}</span>
                      <span
                        className={`status-badge ${row.error_code ? "status-4xx" : ""}`}
                        title={row.error_code ?? undefined}
                      >
                        {row.error_code ?? "—"}
                      </span>
                      <span className="url" title={row.resource ?? undefined}>
                        {resourceLabel(row.resource)}
                      </span>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
