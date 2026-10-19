import { useEffect, useState, type CSSProperties } from "react";

import {
  commands,
  type FieldStats,
  type PayloadKey,
  type Window,
} from "../bindings";
import { useApp } from "../state";

/// Fields grouped as text by the store (`Store::field_stats`); the time is
/// offered by day and by hour rather than to the millisecond.
const TIME_FIELDS: Array<[field: string, label: string]> = [
  ["day", "날짜 (KST)"],
  ["hour", "시간대 (KST)"],
];
/// Mapping entries that are bodies or a timestamp, not something to count
/// by value; their paths are offered under 페이로드 instead.
const NOT_GROUPED: Record<string, true> = {
  event_time: true,
  request: true,
  response: true,
  resources: true,
  raw: true,
};
/// Payload paths listed before the filter narrows them.
const PAYLOAD_LIMIT = 60;

/// Per-value counts of one field over the list on screen. The list is
/// passed as the backend sees it: `ruleId` (a rule, a condition search, or
/// null for every event) and the window's type, dates and text search.
/// `scope` is null while that list is still resolving (a condition search
/// or a rule evaluation in flight); nothing is counted until it is set.
export function StatsDialog({
  caseId,
  logType,
  scope,
  scopeLabel,
  onClose,
}: {
  caseId: string;
  logType: string | null;
  scope: { ruleId: string | null; window: Window } | null;
  /// What the counts are of, for the heading ("전체 이벤트", a rule name…).
  scopeLabel: string;
  onClose: () => void;
}) {
  const { mapping } = useApp();
  const [field, setField] = useState<{ key: string; label: string } | null>(null);
  const [stats, setStats] = useState<FieldStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [payloadKeys, setPayloadKeys] = useState<PayloadKey[]>([]);
  const [keyFilter, setKeyFilter] = useState("");
  // Values shown in full; cleared with each new set of counts.
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    globalThis.addEventListener("keydown", onKey);
    return () => globalThis.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    let stale = false;
    commands.listPayloadKeys(caseId, logType).then((r) => {
      if (!stale && r.status === "ok") setPayloadKeys(r.data);
    });
    return () => {
      stale = true;
    };
  }, [caseId, logType]);

  // The scope is rebuilt on every parent render; its contents are what
  // decide whether the counts are stale.
  const scopeKey = JSON.stringify(scope);
  useEffect(() => {
    setStats(null);
    setError(null);
    setExpanded(new Set());
    if (!field || !scope) return;
    let stale = false;
    commands
      .fieldStats(caseId, scope.ruleId, field.key, scope.window)
      .then((r) => {
        if (stale) return;
        if (r.status === "error") setError(r.error);
        else setStats(r.data);
      });
    return () => {
      stale = true;
    };
  }, [caseId, field, scopeKey]);

  const needle = keyFilter.trim().toLowerCase();
  const shownKeys = payloadKeys
    .filter((k) => needle === "" || k.path.toLowerCase().includes(needle))
    .slice(0, PAYLOAD_LIMIT);
  const top = stats?.values[0]?.count ?? 0;

  const pick = (key: string, label: string) => (
    <button
      key={key}
      className={`stats-field${field?.key === key ? " on" : ""}`}
      aria-pressed={field?.key === key}
      onClick={() => setField({ key, label })}
      title={key}
    >
      {label}
    </button>
  );

  return (
    <div className="raw-backdrop" role="presentation" onClick={onClose}>
      <aside
        className="stats-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="통계"
        onClick={(e) => e.stopPropagation()}
      >
        <header>
          <h2>통계</h2>
          <span className="muted small">{scopeLabel}</span>
          <span className="grow" />
          <button className="sort-toggle" onClick={onClose}>
            닫기
          </button>
        </header>
        <div className="stats-body">
          <nav className="stats-fields" aria-label="필드">
            <h3>필드</h3>
            {mapping
              .filter((entry) => !NOT_GROUPED[entry.field])
              .map((entry) => pick(entry.field, entry.label))}
            <h3>시간</h3>
            {TIME_FIELDS.map(([key, label]) => pick(key, label))}
            <h3>페이로드</h3>
            {payloadKeys.length > 0 && (
              <input
                className="payload-filter"
                type="search"
                value={keyFilter}
                onChange={(e) => setKeyFilter(e.target.value)}
                placeholder="경로 검색"
                aria-label="페이로드 경로 검색"
                spellCheck={false}
                autoComplete="off"
              />
            )}
            {shownKeys.map((k) => pick(k.path, k.path))}
            {payloadKeys.length === 0 && (
              <span className="muted small">수집된 경로가 없습니다</span>
            )}
          </nav>
          <section className="stats-values" aria-live="polite">
            {!field ? (
              <p className="muted">왼쪽에서 필드를 고르면 값별 건수를 보여줍니다.</p>
            ) : !scope ? (
              <p className="muted">목록이 정해지는 중입니다 — 검색·룰 평가가 끝나면 셉니다.</p>
            ) : error ? (
              <p className="error">{error}</p>
            ) : !stats ? (
              <p className="muted">세는 중…</p>
            ) : (
              <>
                <header className="stats-head">
                  <h3>{field.label}</h3>
                  <span>
                    값 {stats.distinct.toLocaleString()}종, {stats.total.toLocaleString()}건
                    {stats.distinct > stats.values.length &&
                      ` (상위 ${stats.values.length}개 표시)`}
                  </span>
                </header>
                {stats.values.length === 0 ? (
                  <p className="muted">이 목록에 이벤트가 없습니다.</p>
                ) : (
                  // Each row is filled behind its text in proportion to the
                  // most frequent value, so the spread reads at a glance.
                  // Rows keep one height; a long value is cut to one line
                  // and opens in full when its row is clicked.
                  <ol className="stats-list">
                    {stats.values.map((v) => {
                      const key = v.value ?? "\u0000";
                      const open = expanded.has(key);
                      return (
                        <li
                          key={key}
                          className={open ? "open" : undefined}
                          style={{ "--fill": `${(v.count / top) * 100}%` } as CSSProperties}
                        >
                          <button
                            className={v.value === null ? "value empty" : "value"}
                            aria-expanded={open}
                            title={open ? undefined : (v.value ?? undefined)}
                            onClick={() =>
                              setExpanded((prev) => {
                                const next = new Set(prev);
                                if (!next.delete(key)) next.add(key);
                                return next;
                              })
                            }
                          >
                            {v.value ?? "값 없음"}
                          </button>
                          <span className="count">{v.count.toLocaleString()}</span>
                          <span className="pct">
                            {((v.count / stats.total) * 100).toFixed(1)}%
                          </span>
                        </li>
                      );
                    })}
                  </ol>
                )}
              </>
            )}
          </section>
        </div>
      </aside>
    </div>
  );
}
