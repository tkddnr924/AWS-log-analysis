import { useState } from "react";

import { FormatCard } from "./FormatCard";
import { useApp } from "../state";
import {
  formatBytes,
  isParseableLogType,
  logTypeLabel,
  PARSEABLE_LOG_TYPES,
} from "../lib/format";
import type { CaseSummary, DetectionRow } from "../bindings";

/// Step 1: pick a directory, review every candidate, exclude what should not
/// be parsed, then start parsing explicitly.
/// Plain words, not the raw status enum: the list is read by an analyst,
/// not by the database.
const STATUS_LABELS: Record<string, string> = {
  done: "완료",
  cancelled: "취소됨",
  failed: "실패",
  running: "진행 중",
};

type LogTab = (typeof PARSEABLE_LOG_TYPES)[number] | "other";

/// One tab per type, no "every type" tab: the grid and the sample below it
/// are read per type, and a mixed list has no single mapping to preview.
const LOG_TABS: ReadonlyArray<{ id: LogTab; label: string }> = [
  ...PARSEABLE_LOG_TYPES.map((id) => ({ id, label: logTypeLabel(id) })),
  { id: "other", label: "기타" },
];

const FILE_BATCH_SIZE = 100;

function belongsToTab(row: DetectionRow, tab: LogTab) {
  if (tab === "other") return !isParseableLogType(row.log_type);
  return row.log_type === tab;
}

function isParseable(row: DetectionRow) {
  return isParseableLogType(row.log_type);
}

export function StartPanel() {
  const { work, root, summary, progress, cases, chooseDirectory, openCase } =
    useApp();

  if (!root) {
    return (
      <div className="landing">
        <div className="hero">
          <img
            className="hero-logo"
            src="/logo.png"
            alt=""
            width={88}
            height={88}
          />
          <h1>AWS Log Analyzer</h1>
          <p className="hero-sub">판별할 AWS 로그 디렉터리를 선택하세요.</p>
          <button
            className="primary hero-cta"
            onClick={() => void chooseDirectory()}
            disabled={work !== "idle"}
          >
            분석할 디렉터리 선택
          </button>
        </div>
        <CaseList cases={cases} onOpen={openCase} />
      </div>
    );
  }

  const busy = work === "scanning" || work === "detecting";

  return (
    <>
      <Toolbar />

      {busy && (
        <p className="muted">
          {work === "scanning"
            ? "스캔 중…"
            : `로그 판별 중… ${progress ? `${progress.done} / ${progress.total}` : ""}`}
        </p>
      )}

      {summary && !busy && <FileReview key={summary.root} />}

      <CaseList cases={cases} onOpen={openCase} />
    </>
  );
}

/// Path, re-pick and the parse action on one line, so the next step is always
/// in the same place regardless of how long the listing is.
function Toolbar() {
  const {
    work,
    root,
    selected,
    caseId,
    startParse,
    chooseDirectory,
    go,
    reset,
  } = useApp();

  return (
    <div className="toolbar">
      <button
        onClick={reset}
        disabled={work !== "idle"}
        title={work === "idle" ? "홈으로" : "작업이 끝난 뒤에 가능합니다"}
      >
        홈
      </button>
      <span className="toolbar-path" title={root ?? ""}>
        {root}
      </span>
      <span className="grow" />
      <button onClick={() => void chooseDirectory()} disabled={work !== "idle"}>
        다른 폴더
      </button>
      {caseId && work === "idle" && (
        <button onClick={() => go("results")}>결과 보기</button>
      )}
      <button
        className="primary"
        onClick={() => void startParse()}
        disabled={work !== "idle" || selected.size === 0}
      >
        파싱 시작
      </button>
    </div>
  );
}

function FileReview() {
  const { rows, summary, selected } = useApp();
  const tabCount = (id: LogTab) =>
    rows.filter((row) => belongsToTab(row, id)).length;
  // Opens on the first tab that has files; an empty first tab would show
  // "no logs" for a directory that has plenty.
  const [chosen, setTab] = useState<LogTab | null>(null);
  const tab =
    chosen ?? LOG_TABS.find(({ id }) => tabCount(id) > 0)?.id ?? LOG_TABS[0].id;
  if (!summary) return null;

  const visibleRows = rows.filter((row) => belongsToTab(row, tab));

  return (
    <>
      <div className="pick-head">
        <h1>
          로그 파일 <strong>{summary.candidate_count}</strong>개 ·{" "}
          {formatBytes(summary.total_bytes ?? 0)} · 선택{" "}
          <strong>{selected.size}</strong>개
        </h1>
        <span className="grow" />
        <SelectAll rows={visibleRows} />
      </div>

      <nav className="log-tabs" role="tablist" aria-label="로그 타입">
        {LOG_TABS.map(({ id, label }) => {
          const count = tabCount(id);
          return (
            <button
              key={id}
              role="tab"
              aria-selected={tab === id}
              aria-controls="detected-file-grid"
              className={tab === id ? "active" : ""}
              disabled={count === 0}
              onClick={() => setTab(id)}
            >
              {label}
              <span>{count.toLocaleString()}</span>
            </button>
          );
        })}
      </nav>

      <FileGrid key={tab} rows={visibleRows} />
      <SamplePreview rows={visibleRows} />
    </>
  );
}

function SelectAll({ rows }: { rows: DetectionRow[] }) {
  const { selected, setSelected } = useApp();
  const selectable = rows.filter(isParseable);
  if (selectable.length === 0) return null;

  const all = selectable.every((row) => selected.has(row.display_path));
  const updateSelection = () => {
    const next = new Set(selected);
    for (const row of selectable) {
      if (all) next.delete(row.display_path);
      else next.add(row.display_path);
    }
    setSelected(next);
  };

  return (
    <button className="linklike" onClick={updateSelection}>
      {all ? "현재 탭 모두 해제" : "현재 탭 모두 선택"}
    </button>
  );
}

function FileGrid({ rows }: { rows: DetectionRow[] }) {
  const { summary, selected, toggle } = useApp();
  const [visibleCount, setVisibleCount] = useState(() =>
    Math.min(rows.length, FILE_BATCH_SIZE),
  );
  const sizes = new Map(
    summary?.candidates.map((candidate) => [
      candidate.display_path,
      candidate.size_bytes,
    ]),
  );

  if (rows.length === 0) {
    return <p className="empty-tab">이 타입의 로그가 없습니다.</p>;
  }

  const visible = rows.slice(0, visibleCount);

  return (
    <div
      className="file-grid"
      id="detected-file-grid"
      role="tabpanel"
      aria-label={`총 ${rows.length.toLocaleString()}개 중 ${visible.length.toLocaleString()}개 표시`}
      onScroll={(event) => {
        const grid = event.currentTarget;
        if (grid.scrollTop + grid.clientHeight < grid.scrollHeight - 44) return;
        setVisibleCount((count) =>
          Math.min(rows.length, count + FILE_BATCH_SIZE),
        );
      }}
    >
      {visible.map((row) => {
        const supported = isParseable(row);
        const on = supported && selected.has(row.display_path);
        const unknown = row.log_type === "unknown";
        const name = row.display_path.split("/").pop() ?? row.display_path;
        return (
          <label
            key={row.display_path}
            className={`file-card${on ? " on" : ""}${unknown ? " unknown" : ""}${supported ? "" : " unsupported"}`}
            title={row.display_path}
          >
            <input
              type="checkbox"
              checked={on}
              disabled={!supported}
              aria-label={row.display_path}
              onChange={() => toggle(row.display_path)}
            />
            <span className="file-name">{name}</span>
            <span className={`file-kind kind-${row.log_type}`}>
              {logTypeLabel(row.log_type)}
            </span>
            <span className="file-meta">
              {unknown
                ? (row.note ?? "판별 안 됨")
                : supported
                  ? formatBytes(sizes.get(row.display_path) ?? 0)
                  : "파싱 미지원"}
            </span>
          </label>
        );
      })}
    </div>
  );
}

/// The format card for one file of the tab: the first selected file, else
/// the first one. Unrecognised files get the card too — seeing the first
/// line is how one tells a Linux syslog from a mis-named export.
function SamplePreview({ rows }: { rows: DetectionRow[] }) {
  const { selected } = useApp();
  const source = rows.find((row) => selected.has(row.display_path)) ?? rows[0];
  if (!source) return null;
  return <FormatCard key={source.display_path} row={source} />;
}

/// Past cases: a row per case with the id first, then where it came from and
/// how big it is. Delete is a two-step action — the case holds the only copy
/// of the parsed evidence.
function CaseList({
  cases,
  onOpen,
}: {
  cases: CaseSummary[];
  onOpen: (caseId: string) => void;
}) {
  const { deleteCase, work } = useApp();
  const [pending, setPending] = useState<string | null>(null);
  if (cases.length === 0) return null;

  return (
    <section className="cases">
      <h2>이전 케이스 {cases.length}개</h2>
      <ul>
        {cases.map((c) => (
          <li
            key={c.case_id}
            className={`case-row${pending === c.case_id ? " confirming" : ""}`}
          >
            {/* The row keeps its identity while confirming: swapping it for a
                prompt hid which case was about to go. Only the actions change;
                the red tint and the filled button carry the warning. */}
            <span className="case-main">
              <code>{c.case_id}</code>
              <span className="case-dir" title={c.input_dir}>
                {c.input_dir}
              </span>
            </span>
            {pending === c.case_id ? (
              // The warning is text, not a tooltip: this deletes the only
              // copy of the parsed evidence, and a tooltip is invisible to
              // keyboard and touch users. It occupies the status and count
              // cells, so the column template is unchanged.
              <span className="case-warning">되돌릴 수 없음</span>
            ) : (
              <>
                <span className={`case-status s-${c.status}`}>
                  {STATUS_LABELS[c.status] ?? c.status}
                </span>
                <span className="case-count">
                  {c.event_count.toLocaleString()}건
                </span>
              </>
            )}
            {pending === c.case_id ? (
              <span className="case-actions">
                <button onClick={() => setPending(null)}>취소</button>
                <button
                  className="danger"
                  onClick={() => void deleteCase(c.case_id)}
                >
                  삭제
                </button>
              </span>
            ) : (
              <span className="case-actions">
                <button
                  className="case-open-btn"
                  onClick={() => onOpen(c.case_id)}
                  disabled={work === "cancelling-rule"}
                >
                  열기
                </button>
                <button
                  className="case-del"
                  title={
                    work === "idle"
                      ? "케이스 삭제"
                      : "작업 중에는 삭제할 수 없습니다"
                  }
                  disabled={work !== "idle"}
                  onClick={() => setPending(c.case_id)}
                >
                  삭제
                </button>
              </span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
