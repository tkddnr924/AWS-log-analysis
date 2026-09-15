import { useState, type ReactNode } from "react";

import type { FieldPreview } from "../bindings";

/// Stored columns, grouped the way an analyst reads an event: what
/// happened, who did it, how it ended.
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
];

/// The payload columns, each its own section; a rule addresses their keys
/// as `<column>.<key>`.
const PAYLOAD: ReadonlyArray<[field: string, title: string]> = [
  ["request", "요청"],
  ["response", "응답"],
  ["resources", "리소스"],
];

/// Booleans are shown as words for the same reason statuses are: the screen
/// is read by an analyst, not by the database.
const BOOL_LABELS: Record<string, string> = { true: "예", false: "아니오" };

/// One stored event as a key/value ledger: sections down the drawer, one
/// aligned row per value. The stored columns come first under their
/// display names; the payload columns follow, flattened to the rule paths
/// (`request.url`, `resources.0.ARN`) that address them, so what is read
/// here is what a rule would test. Empty fields do not take a row.
///
/// Display names ride along on each row (`FieldPreview.label`, from
/// `Field::label`) rather than living in a table here: the rule explanations
/// and the results table read the same source, so a field cannot end up with
/// two names.
export function RecordFields({ preview }: { preview: FieldPreview[] }) {
  const byField = new Map(preview.map((p) => [p.field, p]));

  return (
    <div className="detail">
      {GROUPS.map((group) => {
        const rows = group.fields
          .map((field) => byField.get(field))
          .filter((p): p is FieldPreview => p?.value != null);
        if (rows.length === 0) return null;
        return (
          <section key={group.title} className="detail-section">
            <h3>{group.title}</h3>
            <dl>
              {rows.map((p) => (
                <div key={p.field}>
                  <dt>{p.label}</dt>
                  <dd>{BOOL_LABELS[p.value!] ?? p.value}</dd>
                </div>
              ))}
            </dl>
          </section>
        );
      })}
      {PAYLOAD.map(([field, title]) => {
        const text = byField.get(field)?.value;
        const rows = text ? leaves(parse(text)) : [];
        if (rows.length === 0) return null;
        return (
          <section key={field} className="detail-section payload">
            <h3>
              {title}
              <span>
                룰 경로 <code>{field}.&lt;키&gt;</code>
              </span>
            </h3>
            <dl>
              {rows.map(([key, value]) => (
                <div key={key}>
                  <dt>
                    <code>{key}</code>
                  </dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>
          </section>
        );
      })}
    </div>
  );
}

function parse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/// Every non-null leaf as `[key, text]`, keys spelled the way rules spell
/// them below the column: `url`, `tagging.tagSet.0.key`, `0.ARN`. A null
/// is what a rule sees as missing, so it is not listed.
function leaves(value: unknown): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const walk = (node: unknown, path: string) => {
    if (node === null || node === undefined) return;
    if (Array.isArray(node)) {
      node.forEach((child, index) =>
        walk(child, path ? `${path}.${index}` : String(index)),
      );
    } else if (typeof node === "object") {
      for (const [key, child] of Object.entries(node)) {
        walk(child, path ? `${path}.${key}` : key);
      }
    } else {
      out.push([path, typeof node === "string" ? node : JSON.stringify(node)]);
    }
  };
  walk(value, "");
  return out;
}

/// The stored original, folded under the ledger. Line producers (ALB) are
/// stored wrapped as `{"log_type", "line"}` so the column is valid JSON;
/// the wrapper is ours, so the line is shown bare. JSON records are
/// pretty-printed with keys, strings and numbers told apart.
export function RawRecord({ text }: { text: string | null }) {
  const [copied, setCopied] = useState(false);
  if (text === null) {
    return (
      <details className="raw-json">
        <summary>원본</summary>
        <p className="muted small">원본이 저장되지 않았습니다.</p>
      </details>
    );
  }
  const parsed = parse(text);
  const line = wrappedLine(parsed);
  const shown =
    line ??
    (typeof parsed === "string" ? text : JSON.stringify(parsed, null, 2));
  const copy = () => {
    void navigator.clipboard.writeText(shown).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  };
  return (
    <details className="raw-json">
      <summary>
        {line ? "원본 로그 줄" : "원본 JSON"}
        <span className="grow" />
        <button
          className="linklike raw-copy"
          onClick={(e) => {
            e.preventDefault();
            copy();
          }}
        >
          {copied ? "복사됨" : "복사"}
        </button>
      </summary>
      <pre className={line ? "raw-line" : "raw-code"}>
        {line ?? (typeof parsed === "string" ? text : highlight(shown))}
      </pre>
    </details>
  );
}

/// The bare line behind a `{"log_type": …, "line": …}` wrapper; `null` for
/// anything else.
function wrappedLine(parsed: unknown): string | null {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    return null;
  const keys = Object.keys(parsed);
  const line = (parsed as Record<string, unknown>).line;
  return keys.length === 2 &&
    keys.includes("log_type") &&
    typeof line === "string"
    ? line
    : null;
}

/// Pretty-printed JSON as tokens: keys, strings, numbers, literals and
/// punctuation each get a class. The input is `JSON.stringify` output, so
/// the grammar is exactly this regex.
const JSON_TOKEN =
  /("(?:\\.|[^"\\])*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b/g;

function highlight(json: string): ReactNode[] {
  const parts: ReactNode[] = [];
  let cursor = 0;
  let key = 0;
  for (const match of json.matchAll(JSON_TOKEN)) {
    const start = match.index;
    if (start > cursor) parts.push(json.slice(cursor, start));
    const [token, str, colon, num, lit] = match;
    if (str !== undefined) {
      parts.push(
        <span key={key++} className={colon ? "json-key" : "json-string"}>
          {str}
        </span>,
      );
      if (colon) parts.push(colon);
    } else if (num !== undefined) {
      parts.push(
        <span key={key++} className="json-number">
          {num}
        </span>,
      );
    } else if (lit !== undefined) {
      parts.push(
        <span key={key++} className="json-literal">
          {lit}
        </span>,
      );
    } else {
      parts.push(token);
    }
    cursor = start + token.length;
  }
  if (cursor < json.length) parts.push(json.slice(cursor));
  return parts;
}
