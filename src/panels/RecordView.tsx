import type { FieldPreview } from "../bindings";

/// Grouped the way an analyst reads an event: what happened, who did it,
/// how it ended, and the service-specific payload last.
const GROUPS: Array<{ title: string; fields: string[] }> = [
  {
    title: "이벤트",
    fields: [
      "event_time",
      "event_name",
      "event_source",
      "aws_region",
      "account_id",
    ],
  },
  {
    title: "주체",
    fields: [
      "identity_type",
      "identity_name",
      "identity_arn",
      "source_ip",
      "mfa_authenticated",
      "user_agent",
    ],
  },
  {
    title: "결과",
    fields: ["error_code", "error_message", "read_only", "management_event"],
  },
  { title: "페이로드", fields: ["request", "response", "resources"] },
];

/// One record as grouped, named fields. This is the analysis surface: raw
/// JSON hides the shape, and an unlabelled row hides which field is which.
///
/// Display names ride along on each row (`FieldPreview.label`, from
/// `Field::label`) rather than living in a table here: the rule explanations
/// and the results table read the same source, so a field cannot end up with
/// two names.
export function RecordFields({ preview }: { preview: FieldPreview[] }) {
  const rows = new Map(preview.map((p) => [p.field, p]));
  const shown = (field: string) => {
    const row = rows.get(field);
    return row?.value == null ? null : row;
  };

  return (
    <div className="map-groups">
      {GROUPS.map((g) => (
        <section key={g.title} className="map-group">
          <h3>{g.title}</h3>
          <dl>
            {g.fields
              .map(shown)
              .filter((row): row is FieldPreview => row !== null)
              .map((row) => (
                <div key={row.field}>
                  <dt>{row.label}</dt>
                  <dd>
                    <Value text={row.value!} />
                  </dd>
                </div>
              ))}
          </dl>
          <EmptyNote
            names={g.fields
              .filter((f) => shown(f) === null)
              .map((f) => rows.get(f)?.label ?? f)}
          />
        </section>
      ))}
    </div>
  );
}

function EmptyNote({ names }: { names: string[] }) {
  if (names.length === 0) return null;
  return <p className="map-empty">값 없음 · {names.join(", ")}</p>;
}

/// JSON-valued columns are objects and arrays. Rendering the raw text wastes
/// the width on punctuation, so flatten one level into key/value chips; a
/// scalar is shown as-is.
/// Booleans are shown as words for the same reason statuses are: the screen
/// is read by an analyst, not by the database.
const BOOL_LABELS: Record<string, string> = { true: "예", false: "아니오" };

function Value({ text }: { text: string }) {
  const asBool = BOOL_LABELS[text];
  if (asBool) {
    return <span className="map-value">{asBool}</span>;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return (
      <span className="map-value" title={text}>
        {text}
      </span>
    );
  }
  const entries = flatten(parsed);
  if (entries === null) {
    return (
      <span className="map-value" title={text}>
        {text}
      </span>
    );
  }
  return (
    <ul className="kv">
      {entries.map(([key, val]) => (
        <li key={key}>
          <span className="kv-key">{key}</span>
          <span className="kv-val" title={val}>
            {val}
          </span>
        </li>
      ))}
    </ul>
  );
}

/// `[key, value]` pairs one level deep; `null` when the value is a scalar and
/// should just be printed. Array elements are indexed so `resources` reads as
/// `0.ARN`, matching the mapping path syntax.
function flatten(value: unknown): Array<[string, string]> | null {
  const show = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v));
  if (Array.isArray(value)) {
    return value.flatMap((item, i) =>
      item !== null && typeof item === "object" && !Array.isArray(item)
        ? Object.entries(item).map(([k, v]): [string, string] => [
            `${i}.${k}`,
            show(v),
          ])
        : [[String(i), show(item)] as [string, string]],
    );
  }
  if (value !== null && typeof value === "object") {
    return Object.entries(value).map(([k, v]): [string, string] => [
      k,
      show(v),
    ]);
  }
  return null;
}
