/// Rule source edits the editor makes on the author's behalf. Text-level by
/// design: the draft is often unparseable mid-edit, and the backend parser
/// stays the judge of the result.

const SECTION = /^[ \t]*(?:meta|fields|condition)[ \t]*:/gm;

/// Adds `clause` to the `condition:` section, ANDed with what is there,
/// and returns the new source with the offset to put the caret at (the
/// clause's end). The existing condition is parenthesized when it holds an
/// `or`: `and` binds tighter, so `A or B` + C must become `(A or B) and C`,
/// not `A or (B and C)`. The clause lands at the end of the condition
/// section even when another section follows it. `null` without a
/// `condition:` section.
export function appendCondition(
  source: string,
  clause: string,
): { source: string; caret: number } | null {
  const header = /^([ \t]*)condition[ \t]*:/m.exec(source);
  if (!header) return null;
  const bodyStart = header.index + header[0].length;
  SECTION.lastIndex = bodyStart;
  const next = SECTION.exec(source);
  const close = source.lastIndexOf("}");
  const bodyEnd = next ? next.index : close >= bodyStart ? close : source.length;
  const body = source.slice(bodyStart, bodyEnd);
  const indent = `${header[1]}    `;

  const existing = body.trim();
  if (!existing) {
    const text = `\n${indent}${clause}`;
    const at = bodyStart + body.trimEnd().length;
    return {
      source: source.slice(0, at) + text + source.slice(at),
      caret: at + text.length,
    };
  }

  const start = bodyStart + body.length - body.trimStart().length;
  const end = bodyStart + body.trimEnd().length;
  let grouped = source.slice(start, end);
  if (/\bor\b/.test(grouped)) {
    // A trailing `// comment` would swallow a `)` on its own line.
    const lastLine = grouped.slice(grouped.lastIndexOf("\n") + 1);
    grouped = lastLine.includes("//")
      ? `(${grouped}\n${indent})`
      : `(${grouped})`;
  }
  const text = `${grouped}\n${indent}and ${clause}`;
  return {
    source: source.slice(0, start) + text + source.slice(end),
    caret: start + text.length,
  };
}
