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
  type PayloadKey,
  type RuleHits,
  type RuleOutline,
  type RuleProblem,
} from "../bindings";
import { useApp } from "../state";

const TEMPLATE = `rule my_rule {
    meta:
        name = "새 룰"
        severity = "medium"
    fields:
        $name = event_name == "ConsoleLogin"
    condition:
        $name
}`;

// Field paths take hyphens (`response.x-amz-server-side-encryption`), as
// the backend lexer does; a negative number is matched first, so the
// hyphen only continues a word already begun.
const HIGHLIGHT_TOKEN =
  /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|\/(?:\\.|[^/\\\n])+\/|\$[A-Za-z0-9_]+|\b(?:rule|meta|description|severity|fields|condition|and|or|not|of|true|false|null|exists|missing|contains|icontains|startswith|istartswith|endswith|iendswith|matches|in)\b|(?:==|!=|>=|<=|=|>|<)|-?\b\d+(?:\.\d+)?\b|[A-Za-z_][A-Za-z0-9_.\[\]-]*/g;

/// Payload paths shown at once in the palette; the filter narrows the rest.
const PAYLOAD_PALETTE_LIMIT = 40;

const HIGHLIGHT_KEYWORDS = new Set([
  "rule",
  "meta",
  "name",
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
/// `errorLine` (1-based) gets a stripe behind it, inside the same scrolling
/// layer, so the mark stays on its line.
function highlightRule(source: string, errorLine: number | null): ReactNode[] {
  const parts: ReactNode[] = [];
  if (errorLine !== null) {
    parts.push(
      <span
        key="err"
        className="error-stripe"
        style={{ top: `calc(14px + ${errorLine - 1} * 1.65em)` }}
        aria-hidden="true"
      />,
    );
  }
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
    else if (
      HIGHLIGHT_OPERATORS.has(token) ||
      /^(?:==|!=|>=|<=|=|>|<)$/.test(token)
    )
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

/// The language on one page, for the fold under the palette. The parser is
/// the authority; this is the reminder. Comments are kept out of the
/// skeleton so it never wraps in the side column.
const GRAMMAR_SHAPE = `rule my_rule {
    meta:
        name        = "이름"
        description = "설명"
        severity    = "medium"
        log_type    = "cloudtrail"
    fields:
        $a = event_name == "ConsoleLogin"
        $b = request.bucketName startswith "prod-"
        $c = response.status >= 500
    condition:
        $a and ($b or not $c)
}`;

const GRAMMAR_NOTES: ReadonlyArray<[term: string, note: ReactNode]> = [
  ["rule", "snake_case 식별자, 파일 안에서 유일 (파일명이 된다)"],
  ["name", "목록에 보이는 이름; 없으면 식별자를 보인다"],
  ["description", "선택; 무엇을 잡는지 한 줄"],
  ["severity", "low · medium · high"],
  ["log_type", "생략하면 모든 타입에 적용"],
  ["fields", "조건 하나 = 변수 하나 ($a, $b …)"],
  [
    "condition",
    "변수를 and · or · not · ( ) 로 조합, N of ($a, $b) = N개 이상",
  ],
  [
    "필드",
    "기본 필드는 이름 그대로; 페이로드는 request.키 · response.키 · resources.0.키 · raw.키",
  ],
  ["비교", "== != > >= < <="],
  ["문자열", "contains · startswith · endswith (앞에 i: 대소문자 무시)"],
  ["정규식", "matches /패턴/"],
  ["집합", 'in ("a", "b")'],
  ["존재", "exists · missing"],
  ["값", '"문자열" · 123 · true / false · /정규식/'],
  ["주석", "// 한 줄 · /* 여러 줄 */"],
];

/// The parser speaks in tokens; the card speaks in plain words. What the
/// parser found stays in a code span so the analyst can see the token.
function problemText(problem: RuleProblem | null): ReactNode {
  if (!problem) return "…";
  const m = problem.message;
  const found = m.match(/found (Some\((.+?)\)|None)\s*$/)?.[2];
  const tail = found ? (
    <>
      {" — 여기에 "}
      <code>{found.replace(/^\w+\("?|"?\)$/g, "")}</code>
      {" 이(가) 있습니다"}
    </>
  ) : found === undefined && /found None/.test(m) ? (
    " — 입력이 여기서 끝났습니다"
  ) : null;
  const say = (text: string) => (
    <>
      {text}
      {tail}
    </>
  );
  if (/expected a field name/.test(m))
    return say("조건에 필드 이름이 빠졌습니다: $변수 = 필드 연산 값");
  if (/expected a value/.test(m))
    return say('연산 뒤에 값이 필요합니다: "문자열", 숫자, true/false');
  if (/expected a condition/.test(m))
    return say("condition 에는 $변수와 and / or / not 만 쓸 수 있습니다");
  if (/undefined variable `(\$\w+)`/.test(m)) {
    return `condition 이 fields 에 없는 변수 ${m.match(/undefined variable `(\$\w+)`/)?.[1]} 를 씁니다`;
  }
  if (/unsupported operator `(.+?)`/.test(m)) {
    return `${m.match(/unsupported operator `(.+?)`/)?.[1]} 는 연산자가 아닙니다 — 조각 카드의 연산 중 하나를 쓰세요`;
  }
  if (/missing `condition:`/.test(m)) return "condition: 절이 없습니다";
  if (/unknown section `(.+?)`/.test(m))
    return `${m.match(/unknown section `(.+?)`/)?.[1]} 는 절 이름이 아닙니다 (meta, fields, condition)`;
  if (/expected `rule`/.test(m))
    return say("rule 이름 { … } 로 시작해야 합니다");
  if (/expected rule identifier/.test(m))
    return say("rule 뒤에 이름이 필요합니다");
  if (/needs a string value/.test(m))
    return say('meta 값은 "문자열" 이어야 합니다');
  if (/`matches` needs \/regex\//.test(m))
    return say("matches 뒤에는 /정규식/ 이 와야 합니다");
  if (/invalid regex/.test(m))
    return m.replace(/^.*invalid regex/, "정규식 오류");
  if (/`in` takes string values/.test(m))
    return say('in 안에는 "문자열" 만 쓸 수 있습니다');
  if (/`of` takes variables/.test(m))
    return say("of ( ) 안에는 $변수만 쓸 수 있습니다");
  if (/expected `of` after a count/.test(m))
    return say("숫자 뒤에는 of ( … ) 가 와야 합니다");
  if (/expected `,` or `\)`/.test(m))
    return say("쉼표나 닫는 괄호가 필요합니다");
  if (/expected RBrace/.test(m)) return say("닫는 } 가 필요합니다");
  if (/expected Colon/.test(m)) return say("절 이름 뒤에 : 가 필요합니다");
  if (/expected LBrace/.test(m)) return say("rule 이름 뒤에 { 가 필요합니다");
  if (/expected a section name/.test(m))
    return say("meta: / fields: / condition: 중 하나가 와야 합니다");
  if (/duplicate rule id/.test(m)) return "같은 이름의 룰이 두 번 있습니다";
  if (/unterminated string/.test(m)) return '문자열의 닫는 " 가 없습니다';
  if (/unterminated regex/.test(m)) return "정규식의 닫는 / 가 없습니다";
  if (/unexpected `(.)`/.test(m))
    return `${m.match(/unexpected `(.)`/)?.[1]} 는 이 문법에 없는 글자입니다`;
  return m;
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
  const declaration = /(\$[A-Za-z0-9_]+)\s*=\s*([A-Za-z_][A-Za-z0-9_.\[\]-]*)/g;
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
  logType,
  initial,
  onSave,
  onClose,
  onDelete,
}: {
  caseId: string;
  /// The tab the editor was opened from: its payload paths are offered.
  logType: string | null;
  /// Existing source when editing, empty when adding.
  initial: string;
  onSave: (source: string) => Promise<string | null>;
  onClose: () => void;
  /// Present when editing an existing rule. `user` says whether the file
  /// on disk goes too, or only this case's registration of a shipped rule.
  onDelete?: { user: boolean; run: () => Promise<string | null> };
}) {
  const [source, setSource] = useState(initial || TEMPLATE);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  const [deleting, setDeleting] = useState<"ask" | "run" | null>(null);
  const [outline, setOutline] = useState<RuleOutline | null>(null);
  const [problem, setProblem] = useState<RuleProblem | null>(null);
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
  // The variable builder is a row above the source that opens on demand:
  // most edits are to text that already has its variables.
  const [building, setBuilding] = useState(false);
  const undefinedVariable =
    problem?.message.match(/undefined variable `(\$[A-Za-z0-9_]+)`/)?.[1] ??
    null;
  const errorLine = problem?.line ?? null;
  // Jumps the caret to the offending line so a fix is one keystroke away.
  const jumpToError = () => {
    const el = area.current;
    if (!el || errorLine === null) return;
    const rows = source.split("\n");
    let at = 0;
    for (let i = 0; i < errorLine - 1 && i < rows.length; i += 1) {
      at += rows[i].length + 1;
    }
    el.focus();
    el.setSelectionRange(at, at + (rows[errorLine - 1]?.length ?? 0));
  };
  const variableExists = variables.some(
    (variable) => variable.name === `$${variableName}`,
  );
  // What the parsed data holds under request/response/resources, counted
  // while parsing (docs/04 "페이로드 키"). Nothing is declared for this;
  // it is how an analyst finds `request.bucketName` without reading JSON.
  const [payloadKeys, setPayloadKeys] = useState<PayloadKey[]>([]);
  const [keyFilter, setKeyFilter] = useState("");
  useEffect(() => {
    let stale = false;
    commands.listPayloadKeys(caseId, logType).then((r) => {
      if (!stale && r.status === "ok") setPayloadKeys(r.data);
    });
    return () => {
      stale = true;
    };
  }, [caseId, logType]);
  const needle = keyFilter.trim().toLowerCase();
  const shownKeys = payloadKeys.filter(
    (k) => needle === "" || k.path.toLowerCase().includes(needle),
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
          setProblem(null);
        } else {
          setOutline(null);
          setProblem(r.error);
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
    const field = variableField.trim();
    // The same shape the lexer accepts as a field path.
    if (!name || !/^[A-Za-z0-9_]+$/.test(name)) return;
    if (!/^[A-Za-z_][A-Za-z0-9_.\[\]-]*$/.test(field)) return;
    if (variables.some((variable) => variable.name === `$${name}`)) return;

    const condition = source.match(/^[ \t]*condition\s*:/m);
    if (condition?.index === undefined) return;
    const fieldsStart = source.search(/\bfields\s*:/);
    const fieldsSource = source.slice(
      Math.max(0, fieldsStart),
      condition.index,
    );
    const indent = fieldsSource.match(/^([ \t]+)\$/m)?.[1] ?? "        ";
    const declaration = `${indent}$${name} = ${field} == ""\n`;
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
    replaceSelection(start, start + undefinedVariable.length, replacement);
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

  // One chip: click inserts at the caret; drag drops it where it lands.
  // The browser inserts `text/plain` into a textarea on its own, and the
  // resulting input event keeps React's state in step.
  const chip = (
    key: string,
    label: ReactNode,
    text: string,
    tone: string,
    title?: string,
  ) => (
    <button
      key={key}
      className={`chip chip-${tone}`}
      title={title}
      draggable
      onDragStart={(e) => e.dataTransfer.setData("text/plain", text)}
      onClick={() => insert(text)}
    >
      {label}
    </button>
  );

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
          <span className="grow" />
          <span className="muted small">⌘/Ctrl+Enter 저장 · Esc 닫기</span>
        </header>

        <div className="editor-body">
          <div className="source-column">
            {/* What acts on the text sits above it, like a toolbar. */}
            <div className="editor-toolbar">
              <button
                aria-pressed={building}
                onClick={() => setBuilding((b) => !b)}
              >
                + 변수
              </button>
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
            </div>
            {building && (
              <div className="variable-builder">
                <label>
                  <span>$</span>
                  <input
                    autoFocus
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
                <span className="muted">=</span>
                {/* Typed, not picked: with the payload paths the list is
                    hundreds long. The datalist still offers every field
                    and path as you type. */}
                <input
                  className="variable-field"
                  list="rule-field-paths"
                  value={variableField}
                  onChange={(event) => setVariableField(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      addVariable();
                    }
                  }}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="필드 또는 경로 (예: request.bucketName)"
                  aria-label="새 변수 필드"
                />
                <datalist id="rule-field-paths">
                  {mapping.map((entry) => (
                    <option key={entry.field} value={entry.field}>
                      {entry.label}
                    </option>
                  ))}
                  {payloadKeys.map((key) => (
                    <option key={key.path} value={key.path}>
                      {`${key.events.toLocaleString()}건`}
                    </option>
                  ))}
                </datalist>
                <button
                  onClick={addVariable}
                  disabled={!variableName || variableExists}
                >
                  {variableExists ? "이미 선언됨" : "fields에 추가"}
                </button>
              </div>
            )}
            <div className="source-pane">
              <div className="gutter" ref={gutter} aria-hidden="true">
                {Array.from({ length: lines }, (_, i) => (
                  <span key={i} className={errorLine === i + 1 ? "err" : ""}>
                    {i + 1}
                  </span>
                ))}
              </div>
              <div className="code-stack">
                <pre
                  ref={highlight}
                  className="rule-highlight"
                  aria-hidden="true"
                >
                  {highlightRule(source, errorLine)}
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
          </div>

          <div className="editor-side">
            {/* What the rule says, from the parsed AST — or, while it cannot
                be read, where it breaks. The line is marked in the source
                as well, so this card can be off-screen without the error
                going unseen. */}
            {outline ? (
              <section className="outline">
                <h3>
                  <span className="outline-dot" aria-hidden="true" />
                  {outline.name}
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
                <h3>
                  <span className="outline-dot" aria-hidden="true" />
                  문법 오류
                  {errorLine !== null && (
                    <button className="linklike" onClick={jumpToError}>
                      {errorLine}행으로
                    </button>
                  )}
                </h3>
                <p>{problemText(problem)}</p>
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

            {/* Every insertable token in one card, grouped by a small
                label: drag it into the text or click to insert at the
                caret. Six bordered boxes said "six panels"; this says
                "one palette". */}
            <section className="chips">
              <h3>
                조각<span>끌어 놓거나 눌러서 넣기</span>
              </h3>
              <div className="chip-group">
                <h4>변수</h4>
                <div>
                  {variables.length > 0 ? (
                    variables.map((v) =>
                      chip(
                        v.name,
                        v.name,
                        v.name,
                        "variable",
                        `${v.field} 조건을 참조`,
                      ),
                    )
                  ) : (
                    <span className="chip-empty">
                      fields에 선언한 변수가 여기 나타납니다 (+ 변수)
                    </span>
                  )}
                </div>
              </div>
              <div className="chip-group">
                <h4>필드</h4>
                <div>
                  {mapping.map((entry) =>
                    chip(
                      entry.field,
                      entry.field,
                      entry.field,
                      "field",
                      entry.label,
                    ),
                  )}
                </div>
              </div>
              {/* Every path the parsed payloads hold, most common first.
                  This is where `requestParameters.bucketName` becomes a
                  rule field without anyone declaring it. */}
              <div className="chip-group">
                <h4>
                  페이로드
                  <span>
                    {logType ? `${logType} · ` : ""}
                    {payloadKeys.length.toLocaleString()}개 경로
                  </span>
                </h4>
                {payloadKeys.length > 0 && (
                  <input
                    className="payload-filter"
                    type="search"
                    value={keyFilter}
                    onChange={(event) => setKeyFilter(event.target.value)}
                    placeholder="경로 검색 (예: bucket)"
                    aria-label="페이로드 경로 검색"
                    spellCheck={false}
                    autoComplete="off"
                  />
                )}
                <div>
                  {payloadKeys.length === 0 ? (
                    <span className="chip-empty">
                      이 타입의 이벤트에서 수집된 경로가 없습니다.
                    </span>
                  ) : (
                    <>
                      {shownKeys.slice(0, PAYLOAD_PALETTE_LIMIT).map((key) =>
                        chip(
                          key.path,
                          <>
                            {key.path}
                            <small>{key.events.toLocaleString()}</small>
                          </>,
                          key.path,
                          "payload",
                          `${key.events.toLocaleString()}건에 존재`,
                        ),
                      )}
                      {shownKeys.length > PAYLOAD_PALETTE_LIMIT && (
                        <span className="chip-empty">
                          +
                          {(
                            shownKeys.length - PAYLOAD_PALETTE_LIMIT
                          ).toLocaleString()}
                          개 더 — 검색으로 좁히세요
                        </span>
                      )}
                    </>
                  )}
                </div>
              </div>
              {PALETTE.map((group) => (
                <div key={group.title} className="chip-group">
                  <h4>{group.title}</h4>
                  <div>
                    {group.items.map(([label, text]) =>
                      chip(label, label, text, group.tone),
                    )}
                  </div>
                </div>
              ))}
            </section>

            <details className="grammar">
              <summary>문법 전체</summary>
              <pre>{highlightRule(GRAMMAR_SHAPE, null)}</pre>
              <dl>
                {GRAMMAR_NOTES.map(([term, note]) => (
                  <div key={term}>
                    <dt>{term}</dt>
                    <dd>{note}</dd>
                  </div>
                ))}
              </dl>
            </details>
          </div>
        </div>

        <footer>
          {error ? (
            <p className="error" role="alert" aria-live="assertive">
              {error}
            </p>
          ) : deleting ? (
            <span className="discard-note">
              {onDelete?.user
                ? "이 룰 파일을 지웁니다. 되돌릴 수 없습니다."
                : "이 케이스에서 룰과 매치를 제거합니다. 기본 룰은 다음 케이스에 다시 나타납니다."}
            </span>
          ) : discarding ? (
            <span className="discard-note">변경 내용을 버릴까요?</span>
          ) : (
            <span className="muted small">
              저장하면 이미 파싱된 이벤트에 다시 적용됩니다. 로그를 다시 읽지
              않습니다.
            </span>
          )}
          <span className="grow" />
          {deleting ? (
            <>
              <button
                onClick={() => setDeleting(null)}
                disabled={deleting === "run"}
              >
                취소
              </button>
              <button
                className="danger"
                disabled={deleting === "run"}
                onClick={() => {
                  setDeleting("run");
                  void onDelete?.run().then((message) => {
                    if (message) {
                      setError(message);
                      setDeleting(null);
                    } else {
                      onClose();
                    }
                  });
                }}
              >
                {deleting === "run"
                  ? "삭제 중…"
                  : onDelete?.user
                    ? "룰 삭제"
                    : "케이스에서 제거"}
              </button>
            </>
          ) : discarding ? (
            <>
              <button onClick={() => setDiscarding(false)}>계속 편집</button>
              <button className="danger" onClick={onClose}>
                버리기
              </button>
            </>
          ) : (
            <>
              {onDelete && (
                <button
                  className="editor-delete"
                  onClick={() => setDeleting("ask")}
                  disabled={saving}
                >
                  {onDelete.user ? "룰 삭제" : "케이스에서 제거"}
                </button>
              )}
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
        </footer>
      </aside>
    </div>
  );
}
