import { useEffect, useState } from "react";

import { commands, type DetectionRow, type HeadPreview } from "../bindings";
import { useApp } from "../state";

/// Label chip identifiers travel through drag-and-drop as text; the empty
/// string is the "ignore" label.
const DRAG_TYPE = "text/awslog-field";
const IGNORE = "";

/// The pre-parse format card (FR-4). The head of the chosen file is shown
/// the way the parser sees it: every piece of the first record with the
/// column it feeds written above it, how many head records parse, and which
/// events they carry. On CloudTrail the labels can be moved: dropping one
/// on a piece tells the mapping to read that column from that path.
export function FormatCard({ row }: { row: DetectionRow }) {
  const { root, mapping, setMapping, resetMapping } = useApp();
  const [preview, setPreview] = useState<HeadPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<string | null>(null);

  // Re-previewed through the parser's own resolver whenever the mapping
  // moves, so what is shown is what a parse would store.
  useEffect(() => {
    if (!root || mapping.length === 0) return;
    let stale = false;
    const timer = setTimeout(() => {
      commands
        .previewHead(root, row.display_path, row.log_type, mapping)
        .then((r) => {
          if (stale) return;
          if (r.status === "ok") {
            setPreview(r.data);
            setError(null);
          } else {
            setError(r.error);
          }
        });
    }, 150);
    return () => {
      stale = true;
      clearTimeout(timer);
    };
  }, [root, row.display_path, row.log_type, mapping]);

  // A label dropped on a piece: that column now reads this path. "Ignore"
  // takes the path away from whichever columns read it.
  const assign = (field: string, path: string) => {
    setPicked(null);
    if (field === IGNORE) {
      setMapping(
        mapping.map((m) =>
          m.sources.includes(path)
            ? { ...m, sources: m.sources.filter((s) => s !== path) }
            : m,
        ),
      );
      return;
    }
    setMapping(
      mapping.map((m) => (m.field === field ? { ...m, sources: [path] } : m)),
    );
  };

  const name = row.display_path.split("/").pop() ?? row.display_path;
  // Line formats are shown by position, like WebLog: the token is the
  // whole piece, and a JSON key would only repeat the label.
  const positional =
    row.log_type === "alb_access" || row.log_type === "unknown";
  const inFirst = new Set(preview?.pieces.map((p) => p.path));
  const elsewhere = preview?.paths.filter((p) => !inFirst.has(p.name)) ?? [];

  // Three groups, not one wall: what lands in a stored column (in the
  // column order the rest of the app uses), what becomes a rule path, and
  // what nothing reads. The last is folded — a CloudTrail record has
  // dozens of keys and most of them are noise until a label is dropped.
  const pieces = preview?.pieces ?? [];
  const order = new Map(mapping.map((m, i) => [m.field, i]));
  const builtin = pieces
    .filter((p) => p.field && !p.field.includes("."))
    .sort(
      (a, b) =>
        (order.get(a.field ?? "") ?? 99) - (order.get(b.field ?? "") ?? 99),
    );
  const payload = pieces.filter((p) => p.field?.includes("."));
  const unused = pieces.filter((p) => !p.field);
  const absent = preview?.editable
    ? mapping.filter(
        (m) =>
          !pieces.some(
            (p) => p.field === m.field || p.field?.startsWith(`${m.field}.`),
          ),
      )
    : [];

  const renderPiece = (piece: HeadPreview["pieces"][number]) => {
    const chosen = picked === piece.path;
    const kind = piece.field
      ? piece.field.includes(".")
        ? "payload"
        : "builtin"
      : "unused";
    return (
      <button
        key={piece.path}
        role="listitem"
        className={`piece ${kind}${chosen ? " picked" : ""}`}
        title={
          piece.field
            ? `${piece.path} → ${piece.field}`
            : `${piece.path} (저장하지 않음)`
        }
        aria-pressed={chosen}
        onClick={() =>
          preview?.editable && setPicked(chosen ? null : piece.path)
        }
        onDragOver={(e) => {
          if (preview?.editable) e.preventDefault();
        }}
        onDrop={(e) => {
          if (!preview?.editable) return;
          e.preventDefault();
          if (e.dataTransfer.types.includes(DRAG_TYPE))
            assign(e.dataTransfer.getData(DRAG_TYPE), piece.path);
        }}
      >
        {kind === "builtin" && (
          <small className="piece-label">{piece.label}</small>
        )}
        <span className="piece-body">
          {!positional && (
            <code className="piece-key">
              {kind === "payload" ? piece.field : piece.path}
            </code>
          )}
          <span className="piece-value">{piece.value}</span>
        </span>
      </button>
    );
  };

  return (
    <section className="format-card">
      <header>
        <code className="format-file">{name}</code>
        {preview && <Status preview={preview} row={row} />}
        <span className="grow" />
        {row.record_count_estimate !== null && (
          <span className="muted small">
            전체 {row.record_count_estimate.toLocaleString()}개
            {row.estimated ? " 추정" : ""}
          </span>
        )}
        {preview?.editable && (
          <button onClick={() => void resetMapping()}>기본값으로</button>
        )}
      </header>

      {error && (
        <p className="error small" role="alert">
          {error}
        </p>
      )}

      {preview && preview.event_names.length > 0 && (
        <div className="event-mix" aria-label="선두 레코드의 이벤트 구성">
          {preview.event_names.map((n) => (
            <span key={n.name} title={`${n.count.toLocaleString()}건`}>
              <code>{n.name}</code>
              <small>{n.count.toLocaleString()}</small>
            </span>
          ))}
        </div>
      )}

      {preview && (
        <div className="piece-groups">
          <section className="piece-group">
            <h3>
              저장 필드
              <span>레코드에서 읽어 컬럼에 넣는 값</span>
            </h3>
            <div className="pieces" role="list">
              {builtin.map(renderPiece)}
            </div>
            {absent.length > 0 && (
              <p className="piece-absent">
                값 없음 · {absent.map((m) => m.label).join(", ")}
              </p>
            )}
          </section>
          {payload.length > 0 && (
            <section className="piece-group">
              <h3>
                페이로드
                <span>
                  통째로 저장되고 룰에서 이 경로로 접근 — 매핑할 필요 없음
                </span>
              </h3>
              <div className="pieces" role="list">
                {payload.map(renderPiece)}
              </div>
            </section>
          )}
          {unused.length > 0 && (
            <details className="piece-group folded">
              <summary>
                저장하지 않는 키 {unused.length.toLocaleString()}개
                {preview.editable && (
                  <span> — 라벨을 붙이면 그 컬럼으로 저장됩니다</span>
                )}
              </summary>
              <div className="pieces" role="list">
                {unused.map(renderPiece)}
              </div>
            </details>
          )}
        </div>
      )}

      {preview?.editable && (
        <div className="label-palette" aria-label="라벨">
          <span className="palette-hint">
            {picked
              ? `${picked} 에 붙일 라벨을 누르세요`
              : "라벨을 조각에 끌어다 놓거나, 조각을 고른 뒤 라벨을 누르세요"}
          </span>
          <div>
            {mapping.map((m) => (
              <span
                key={m.field}
                className="label-chip"
                draggable
                role="button"
                tabIndex={0}
                title={m.field}
                onDragStart={(e) => e.dataTransfer.setData(DRAG_TYPE, m.field)}
                onClick={() => picked && assign(m.field, picked)}
                onKeyDown={(e) => {
                  if ((e.key === "Enter" || e.key === " ") && picked) {
                    e.preventDefault();
                    assign(m.field, picked);
                  }
                }}
              >
                {m.label}
              </span>
            ))}
            <span
              className="label-chip ignore"
              draggable
              role="button"
              tabIndex={0}
              onDragStart={(e) => e.dataTransfer.setData(DRAG_TYPE, IGNORE)}
              onClick={() => picked && assign(IGNORE, picked)}
              onKeyDown={(e) => {
                if ((e.key === "Enter" || e.key === " ") && picked) {
                  e.preventDefault();
                  assign(IGNORE, picked);
                }
              }}
            >
              무시
            </span>
          </div>
        </div>
      )}

      {preview && elsewhere.length > 0 && (
        <details className="more-paths">
          <summary>
            그 외 {elsewhere.length.toLocaleString()}개 경로 — 첫 레코드에는
            없고 선두 {preview.records.toLocaleString()}개 안에 있는 것
          </summary>
          <div>
            {elsewhere.map((p) => (
              <span key={p.name} className="path-chip">
                <code>{p.name}</code>
                <small>{p.count.toLocaleString()}</small>
              </span>
            ))}
          </div>
        </details>
      )}
    </section>
  );
}

/// "All parsed", how many are missing a time or an event name (which a
/// record needs to land in the results), or — for a file no parser claims —
/// why, so the analyst is not left guessing from "기타".
function Status({ preview, row }: { preview: HeadPreview; row: DetectionRow }) {
  const missing = preview.records - preview.mapped;
  if (row.log_type === "unknown") {
    return (
      <span className="format-status warn">
        AWS 로그로 판별되지 않음{row.note ? ` — ${row.note}` : ""} · 선두{" "}
        {preview.records.toLocaleString()}줄
      </span>
    );
  }
  if (preview.records === 0) {
    return (
      <span className="format-status warn">선두에서 레코드를 찾지 못함</span>
    );
  }
  if (missing === 0) {
    return (
      <span className="format-status ok">
        선두 {preview.records.toLocaleString()}개 레코드 모두 파싱됨
      </span>
    );
  }
  return (
    <span className="format-status warn">
      선두 {preview.records.toLocaleString()}개 중 {missing.toLocaleString()}
      개는 시각·이벤트 이름이 없음
    </span>
  );
}
