import { useEffect, useState } from "react";

import { commands, type FieldPreview, type MappingEntry } from "../bindings";
import { RecordFields } from "./RecordView";
import { useApp } from "../state";

/// Human names for the stored CloudTrail columns. The paths beside them are
/// the real JSON keys, so this table is the contract between JSON input and
/// storage. ALB access logs use their fixed positional schema instead.
export function MappingEditor({ record }: { record: string }) {
  const { mapping, setMapping, resetMapping } = useApp();
  const [preview, setPreview] = useState<FieldPreview[]>([]);
  const [open, setOpen] = useState(false);

  // Previewed through the same resolver the parser uses, so what is shown
  // here is exactly what gets stored.
  useEffect(() => {
    if (mapping.length === 0) return;
    let stale = false;
    commands.previewMapping(record, mapping).then((r) => {
      if (!stale && r.status === "ok") setPreview(r.data);
    });
    return () => {
      stale = true;
    };
  }, [record, mapping]);

  const valueOf = (field: string) =>
    preview.find((p) => p.field === field)?.value ?? null;
  const mapped = preview.filter((p) => p.value !== null).length;

  const edit = (field: string, text: string) => {
    const sources = text
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    setMapping(mapping.map((m) => (m.field === field ? { ...m, sources } : m)));
  };

  return (
    <section className="mapping">
      <header>
        <button className="linklike" onClick={() => setOpen(!open)}>
          {open ? "▾" : "▸"} 필드 매핑
        </button>
        <span className="muted small">
          {mapped}/{preview.length} 매핑됨
        </span>
        <span className="grow" />
        {open && (
          <button onClick={() => void resetMapping()}>기본값으로</button>
        )}
      </header>

      {open ? (
        <table className="map-table">
          <thead>
            <tr>
              <th>저장 필드</th>
              <th>JSON 경로 — 쉼표로 구분, 앞에서부터 시도</th>
              <th>이 레코드의 값</th>
            </tr>
          </thead>
          <tbody>
            {mapping.map((m) => (
              <Row
                key={m.field}
                entry={m}
                value={valueOf(m.field)}
                onEdit={edit}
              />
            ))}
          </tbody>
        </table>
      ) : (
        // Collapsed: only the fields that actually resolved, as a summary.
        <RecordFields preview={preview} />
      )}
    </section>
  );
}

function Row({
  entry,
  value,
  onEdit,
}: {
  entry: MappingEntry;
  value: string | null;
  onEdit: (field: string, text: string) => void;
}) {
  return (
    <tr className={value === null ? "unmapped" : ""}>
      <td>
        <span className="map-name">{entry.label}</span>
        <code className="map-col">{entry.field}</code>
      </td>
      <td>
        <input
          className="map-input"
          value={entry.sources.join(", ")}
          title={entry.sources.join(", ")}
          spellCheck={false}
          autoComplete="off"
          placeholder="eventName, operation…"
          aria-label={`${entry.field} 경로`}
          onChange={(e) => onEdit(entry.field, e.target.value)}
        />
      </td>
      <td>
        {value === null ? (
          <span className="map-miss">값 없음</span>
        ) : (
          <span className="map-value" title={value}>
            {value}
          </span>
        )}
      </td>
    </tr>
  );
}
