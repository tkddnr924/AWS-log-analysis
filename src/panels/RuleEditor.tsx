import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import {
  commands,
  type MappingEntry,
  type RuleHits,
  type RuleOutline,
} from "../bindings";
import { useApp } from "../state";

const TEMPLATE = `rule my_rule {
    meta:
        description = "설명"
        severity = "medium"
    fields:
        $name = event_name == "ConsoleLogin"
    condition:
        $name
}`;

const HIGHLIGHT_TOKEN =
  /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|\/(?:\\.|[^/\\\n])+\/|\$[A-Za-z0-9_]+|\b(?:rule|meta|description|severity|fields|condition|and|or|not|of|true|false|null|exists|missing|contains|icontains|startswith|istartswith|endswith|iendswith|matches|in)\b|(?:==|!=|>=|<=|=|>|<)|-?\b\d+(?:\.\d+)?\b|[A-Za-z_][A-Za-z0-9_.\[\]]*/g;

const HIGHLIGHT_KEYWORDS = new Set([
  "rule",
  "meta",
  "description",
  "severity",
  "fields",
  "condition",
]);
const HIGHLIGHT_OPERATORS = new Set([
  "and",
  "or",
  "not",
  "of",
  "exists",
  "missing",
  "contains",
  "icontains",
  "startswith",
  "istartswith",
  "endswith",
  "iendswith",
  "matches",
  "in",
]);

/// Mirrors the lexer classes without interpreting the rule. React escapes
/// every token, so a pasted `<script>` stays text rather than becoming HTML.
function highlightRule(source: string): ReactNode[] {
  const parts: ReactNode[] = [];
  let cursor = 0;
  let key = 0;
  for (const match of source.matchAll(HIGHLIGHT_TOKEN)) {
    const start = match.index;
    if (start > cursor) parts.push(source.slice(cursor, start));
    const token = match[0];
    let kind = "field";
    if (token.startsWith("//") || token.startsWith("/*")) kind = "comment";
    else if (token.startsWith('"')) kind = "string";
    else if (token.startsWith("/")) kind = "regex";
    else if (token.startsWith("$")) kind = "variable";
    else if (HIGHLIGHT_KEYWORDS.has(token)) kind = "keyword";
    else if (HIGHLIGHT_OPERATORS.has(token) || /^(?:==|!=|>=|<=|=|>|<)$/.test(token))
      kind = "operator";
    else if (/^(?:true|false|null)$/.test(token)) kind = "literal";
    else if (/^-?\d/.test(token)) kind = "number";
    parts.push(
      <span className={`syntax-${kind}`} key={key++}>
        {token}
      </span>,
    );
    cursor = start + token.length;
  }
  if (cursor < source.length) parts.push(source.slice(cursor));
  return parts;
}

type PaletteTone = "field" | "operator" | "logic" | "snippet";

/// The operators are exactly the ones `rule::parser` accepts. A token the
/// parser does not know would only surface as a parse error after the author
/// had written the whole rule around it.
const PALETTE: Array<{
  title: string;
  tone: PaletteTone;
  items: Array<[label: string, text: string]>;
}> = [
  {
    title: "연산",
    tone: "operator",
    items: [
      ["==", " == "],
      ["!=", " != "],
      ["contains", " contains "],
      ["icontains", " icontains "],
      ["startswith", " startswith "],
      ["istartswith", " istartswith "],
      ["endswith", " endswith "],
      ["iendswith", " iendswith "],
      ["matches", " matches //"],
      ["in (…)", ' in ("", "")'],
      [">", " > "],
      [">=", " >= "],
      ["<", " < "],
      ["<=", " <= "],
      ["exists", " exists"],
      ["missing", " missing"],
    ],
  },
  {
    title: "논리",
    tone: "logic",
    items: [
      ["and", " and "],
      ["or", " or "],
      ["not", "not "],
      ["( )", "()"],
      ["N of (…)", "2 of ($a, $b)"],
    ],
  },
  {
    title: "조각",
    tone: "snippet",
    items: [
      ["루트 사용", '$root = identity_type == "Root"'],
      ["MFA 없음", "$nomfa = mfa_authenticated == false"],
      ["실패한 호출", "$failed = error_code exists"],
      ["삭제 계열", '$del = event_name startswith "Delete"'],
      ["콘솔 로그인", '$login = event_name == "ConsoleLogin"'],
    ],
  },
];

/// The insertable field tokens, taken from the backend's mapping: the column
/// keys a rule may name and the names they are shown under both come from
/// `Field`, so the palette cannot offer a column the engine does not have.
function fieldGroup(entries: MappingEntry[]) {
  return {
    title: "필드",
    tone: "field" as const,
    items: entries.map((e): [label: string, text: string] => [
      e.label,
      e.field,
    ]),
  };
}

type DeclaredVariable = {
  name: string;
  field: string;
};

/// The backend remains the parser of record. This small scan only powers
/// authoring controls: declarations between `fields:` and `condition:` become
/// clickable references, even while the rest of the rule is incomplete.
function declaredVariables(source: string): DeclaredVariable[] {
  const fields = source.search(/\bfields\s*:/);
  const condition = source.search(/\bcondition\s*:/);
  if (fields < 0 || condition <= fields) return [];

  const variables: DeclaredVariable[] = [];
  const declaration =
    /(\$[A-Za-z0-9_]+)\s*=\s*([A-Za-z_][A-Za-z0-9_.\[\]]*)/g;
  for (const match of source.slice(fields, condition).matchAll(declaration)) {
    variables.push({ name: match[1], field: match[2] });
  }
  return variables;
}

/// Writes one rule. The source is the rule language itself rather than a form:
/// the conditions an analyst needs (and/or/not over several fields) do not fit
/// a fixed set of inputs, and the text is what ends up in `cases/rules/`.
export function RuleEditor({
  caseId,
  initial,
  onSave,
  onClose,
}: {
  caseId: string;
  /// Existing source when editing, empty when adding.
  initial: string;
  onSave: (source: string) => Promise<string | null>;
  onClose: () => void;
}) {
  const [source, setSource] = useState(initial || TEMPLATE);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  const [outline, setOutline] = useState<RuleOutline | null>(null);
  const [syntaxError, setSyntaxError] = useState<string | null>(null);
  const [hits, setHits] = useState<RuleHits | null>(null);
  const [counting, setCounting] = useState(false);
  // The mapping the app already loaded at startup: the palette needs the
  // column names, and fetching them again per editor open would leave the
  // field group empty on first paint.
  const { mapping } = useApp();
  const area = useRef<HTMLTextAreaElement>(null);
  const pendingSelection = useRef<[start: number, end: number] | null>(null);
  const highlight = useRef<HTMLPreElement>(null);
  const gutter = useRef<HTMLDivElement>(null);
  // Mirrors `source` for the scan below, which finishes after the text may
  // have moved on. Same pattern as `workRef` in state.tsx.
  const counted = useRef(source);
  counted.current = source;
  const dirty = source !== (initial || TEMPLATE);

  const lines = useMemo(() => source.split("\n").length, [source]);
  const variables = useMemo(() => declaredVariables(source), [source]);
  const [variableName, setVariableName] = useState("");
  const [variableField, setVariableField] = useState("event_name");
  const undefinedVariable =
    syntaxError?.match(/undefined variable `(\$[A-Za-z0-9_]+)`/)?.[1] ?? null;
  const variableExists = variables.some(
    (variable) => variable.name === `$${variableName}`,
  );

  useEffect(() => {
    area.current?.focus();
  }, []);

  // The rule is parsed as it is typed, and the sentence comes from the parsed
  // AST — so what is shown is what the engine would evaluate, not a guess
  // made from the text. Parsing is cheap; counting is not, hence the button.
  useEffect(() => {
    let stale = false;
    const timer = setTimeout(() => {
      commands.explainRule(source).then((r) => {
        if (stale) return;
        if (r.status === "ok") {
          setOutline(r.data);
          setSyntaxError(null);
        } else {
          setOutline(null);
          setSyntaxError(r.error);
        }
      });
    }, 250);
    return () => {
      stale = true;
      clearTimeout(timer);
    };
  }, [source]);

  // Esc asks first when there is something to lose: rule text is not cheap
  // to retype, and a stray key should not throw it away.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        void save();
        return;
      }
      if (e.key !== "Escape") return;
      if (dirty) setDiscarding(true);
      else onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, dirty, source]);

  const replaceSelection = (
    start: number,
    end: number,
    text: string,
    selection: [number, number] = [start + text.length, start + text.length],
  ) => {
    pendingSelection.current = selection;
    setSource(source.slice(0, start) + text + source.slice(end));
    setError(null);
    setHits(null);
  };

  const insert = (text: string) => {
    const el = area.current;
    if (!el) return;
    replaceSelection(el.selectionStart, el.selectionEnd, text);
  };

  const addVariable = () => {
    const name = variableName.replace(/^\$/, "").trim();
    if (!name || !/^[A-Za-z0-9_]+$/.test(name) || !variableField) return;
    if (variables.some((variable) => variable.name === `$${name}`)) return;

    const condition = source.match(/^[ \t]*condition\s*:/m);
    if (condition?.index === undefined) return;
    const fieldsStart = source.search(/\bfields\s*:/);
    const fieldsSource = source.slice(Math.max(0, fieldsStart), condition.index);
    const indent = fieldsSource.match(/^([ \t]+)\$/m)?.[1] ?? "        ";
    const declaration = `${indent}$${name} = ${variableField} == ""\n`;
    const valueStart = condition.index + declaration.lastIndexOf('""') + 1;
    replaceSelection(condition.index, condition.index, declaration, [
      valueStart,
      valueStart,
    ]);
    setVariableName("");
  };

  const replaceUndefinedVariable = (replacement: string) => {
    if (!undefinedVariable) return;
    const condition = source.search(/\bcondition\s*:/);
    const start = source.indexOf(undefinedVariable, Math.max(0, condition));
    if (start < 0) return;
    replaceSelection(
      start,
      start + undefinedVariable.length,
      replacement,
    );
  };

  // Restore after React has committed the controlled textarea value. A
  // requestAnimationFrame can run before that commit and React then moves the
  // caret to the end of the document.
  useLayoutEffect(() => {
    const selection = pendingSelection.current;
    const el = area.current;
    if (!selection || !el) return;
    pendingSelection.current = null;
    el.focus();
    el.setSelectionRange(selection[0], selection[1]);
  }, [source]);

  // The backend parses before writing, so its message is the authority on
  // what is wrong; there is no second validator here to disagree with it.
  const save = async () => {
    setSaving(true);
    const message = await onSave(source);
    setSaving(false);
    if (message) setError(message);
    else onClose();
  };

  // A full scan per press, so it is a button and not a keystroke handler: on a
  // large case this walks every event. `counting` also keeps a second scan
  // from starting while one is in flight.
  const count = async () => {
    if (counting) return;
    const asked = source;
    setCounting(true);
    const r = await commands.countRuleMatches(caseId, asked);
    setCounting(false);
    // Typing while the scan ran means this number answers text that no longer
    // exists; showing it would label the new rule with the old rule's count.
    if (counted.current !== asked) return;
    if (r.status === "error") return setError(r.error);
    setHits(r.data);
  };

  return (
    <div
      className="raw-backdrop"
      role="presentation"
      // A backdrop click must not discard edits by accident.
      onClick={() => (dirty ? setDiscarding(true) : onClose())}
    >
      <aside
        className="rule-editor"
        role="dialog"
        aria-modal="true"
        aria-label="룰 편집"
        onClick={(e) => e.stopPropagation()}
      >
        <header>
          <h2>{initial ? "룰 수정" : "룰 추가"}</h2>
          <span className="muted small">⌘/Ctrl+Enter 저장 · Esc 닫기</span>
          <span className="grow" />
          {discarding ? (
            <>
              <span className="discard-note">변경 내용을 버릴까요?</span>
              <button onClick={() => setDiscarding(false)}>계속 편집</button>
              <button className="danger" onClick={onClose}>
                버리기
              </button>
            </>
          ) : (
            <>
              <button onClick={() => (dirty ? setDiscarding(true) : onClose())}>
                취소
              </button>
              <button
                className="primary"
                onClick={() => void save()}
                disabled={saving}
              >
                {saving ? "저장 중…" : "저장"}
              </button>
            </>
          )}
        </header>

        <div className="editor-body">
          <div className="source-pane">
            <div className="gutter" ref={gutter} aria-hidden="true">
              {Array.from({ length: lines }, (_, i) => (
                <span key={i}>{i + 1}</span>
              ))}
            </div>
            <div className="code-stack">
              <pre
                ref={highlight}
                className="rule-highlight"
                aria-hidden="true"
              >
                {highlightRule(source)}
              </pre>
              <textarea
                ref={area}
                className="rule-source"
                value={source}
                spellCheck={false}
                autoComplete="off"
                aria-label="룰 정의"
                onScroll={(e) => {
                  if (highlight.current) {
                    highlight.current.scrollTop = e.currentTarget.scrollTop;
                    highlight.current.scrollLeft = e.currentTarget.scrollLeft;
                  }
                  if (gutter.current) {
                    gutter.current.scrollTop = e.currentTarget.scrollTop;
                  }
                }}
                onChange={(e) => {
                  setSource(e.target.value);
                  setError(null);
                  setHits(null);
                }}
              />
            </div>
          </div>

          <div className="editor-side">
            {/* What the rule says, from the parsed AST. A red panel here means
                the engine cannot read the rule at all. */}
            {outline ? (
              <section className="outline">
                <h3>
                  {outline.description || outline.rule_id}
                  <code>{outline.rule_id}</code>
                </h3>
                <p>{outline.explanation}</p>
              </section>
            ) : (
              <section
                className="outline broken"
                role="status"
                aria-live="polite"
              >
                <h3>문법 오류</h3>
                <p>{syntaxError ?? "…"}</p>
                {undefinedVariable && variables.length > 0 && (
                  <div className="variable-fixes">
                    <span>{undefinedVariable} 대신</span>
                    {variables.map((variable) => (
                      <button
                        key={variable.name}
                        onClick={() => replaceUndefinedVariable(variable.name)}
                      >
                        {variable.name}
                      </button>
                    ))}
                  </div>
                )}
              </section>
            )}

            <p className="actions">
              <button
                onClick={() => void count()}
                disabled={counting || !outline}
              >
                {counting ? "세는 중…" : "일치 건수 확인"}
              </button>
              {hits !== null && (
                <span className="hit-count" role="status" aria-live="polite">
                  <strong>{hits.hits.toLocaleString()}</strong>건 / 전체{" "}
                  {hits.total.toLocaleString()}건
                </span>
              )}
            </p>
            <section className="variable-tools">
              <div className="palette-heading">
                <h4>변수</h4>
                <span>fields에서 선언 · condition에서 사용</span>
              </div>
              {variables.length > 0 ? (
                <div className="declared-variables">
                  {variables.map((variable) => (
                    <button
                      key={variable.name}
                      title={`${variable.field} 조건을 참조`}
                      onClick={() => insert(variable.name)}
                    >
                      <code>{variable.name}</code>
                      <span>{variable.field}</span>
                    </button>
                  ))}
                </div>
              ) : (
                <p className="variable-empty">아직 선언된 변수가 없습니다.</p>
              )}
              <div className="variable-builder">
                <label>
                  <span>$</span>
                  <input
                    value={variableName}
                    onChange={(event) =>
                      setVariableName(
                        event.target.value.replace(/[^A-Za-z0-9_]/g, ""),
                      )
                    }
                    onKeyDown={(event) => {
                      if (event.key === "Enter") {
                        event.preventDefault();
                        addVariable();
                      }
                    }}
                    placeholder="변수 이름"
                    aria-label="새 변수 이름"
                  />
                </label>
                <select
                  value={variableField}
                  onChange={(event) => setVariableField(event.target.value)}
                  aria-label="새 변수 필드"
                >
                  {mapping.map((entry) => (
                    <option key={entry.field} value={entry.field}>
                      {entry.label}
                    </option>
                  ))}
                </select>
                <button
                  onClick={addVariable}
                  disabled={!variableName || variableExists}
                >
                  {variableExists ? "이미 선언됨" : "선언 추가"}
                </button>
              </div>
              <p className="variable-help">
                선언을 추가하면 값 위치가 선택됩니다. 바로 조건 값을 입력하세요.
              </p>
            </section>
            {[fieldGroup(mapping), ...PALETTE].map((group) => (
              <section
                key={group.title}
                className={`palette palette-${group.tone}`}
              >
                <h4>{group.title}</h4>
                <div>
                  {group.items.map(([label, text]) => (
                    <button key={label} onClick={() => insert(text)}>
                      {label}
                    </button>
                  ))}
                </div>
              </section>
            ))}
          </div>
        </div>

        {error && (
          <p className="error" role="alert" aria-live="assertive">
            {error}
          </p>
        )}
        <p className="muted small">
          저장하면 이미 파싱된 이벤트에 다시 적용됩니다. 로그를 다시 읽지
          않습니다.
        </p>
      </aside>
    </div>
  );
}
