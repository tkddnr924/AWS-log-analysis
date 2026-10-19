import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Channel } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { isParseableLogType } from "./lib/format";
import { createRuleTasks } from "./lib/ruleTasks";
import {
  commands,
  events,
  type CaseSummary,
  type DetectionRow,
  type ParseResult,
  type MappingEntry,
  type ConditionSearch,
  type RuleHits,
  type ScanSummary,
} from "./bindings";

/// Which screen is shown. Separate from `work` so navigating away from a
/// running parse does not stop it or lose its progress.
export type Screen = "start" | "parsing" | "results";

/// What the backend is doing, independent of what is on screen.
export type Work =
  | "idle"
  | "scanning"
  | "detecting"
  | "parsing"
  | "evaluating"
  | "cancelling-rule";

export type Progress = {
  done: number;
  total: number;
  records: number;
  cancelRequested: boolean;
};

type State = {
  screen: Screen;
  work: Work;
  root: string | null;
  summary: ScanSummary | null;
  rows: DetectionRow[];
  /// Display paths the user kept. Only these are parsed.
  selected: Set<string>;
  progress: Progress | null;
  parsed: ParseResult | null;
  caseId: string | null;
  cases: CaseSummary[];
  notice: string | null;
  /// CloudTrail JSON-path mapping. ALB access logs use a fixed schema.
  mapping: MappingEntry[];
  setMapping: (mapping: MappingEntry[]) => void;
  resetMapping: () => Promise<void>;
  go: (screen: Screen) => void;
  openCase: (caseId: string) => void;
  deleteCase: (caseId: string) => Promise<void>;
  setNotice: (notice: string | null) => void;
  toggle: (displayPath: string) => void;
  setSelected: (paths: Set<string>) => void;
  chooseDirectory: () => Promise<void>;
  startParse: () => Promise<void>;
  cancelParse: () => void;
  evaluateRule: (caseId: string, ruleId: string) => Promise<number>;
  countRuleMatches: (caseId: string, source: string) => Promise<RuleHits>;
  /// Runs a condition typed into the results search; `null` when the text
  /// is not a condition. Replaces a running or waiting search; rejects with
  /// `SupersededError` when a newer one replaced this one first.
  searchCondition: (
    caseId: string,
    ruleId: string | null,
    query: string,
  ) => Promise<ConditionSearch | null>;
  /// Drops the search, running or waiting; evaluations are left alone.
  cancelSearch: () => Promise<void>;
  cancelRule: () => Promise<void>;
  reset: () => void;
};

const Ctx = createContext<State | null>(null);

export function useApp() {
  const value = useContext(Ctx);
  if (!value) throw new Error("useApp outside AppStateProvider");
  return value;
}

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [screen, setScreen] = useState<Screen>("start");
  const [work, setWork] = useState<Work>("idle");
  const [root, setRoot] = useState<string | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [rows, setRows] = useState<DetectionRow[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [progress, setProgress] = useState<Progress | null>(null);
  const [parsed, setParsed] = useState<ParseResult | null>(null);
  const [caseId, setCaseId] = useState<string | null>(null);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [mapping, setMapping] = useState<MappingEntry[]>([]);

  // Discards responses from a run the user already moved on from.
  const runRef = useRef(0);
  // Mirrors `work` for the listeners below, which are registered once and
  // would otherwise close over the initial value.
  const workRef = useRef<Work>("idle");
  workRef.current = work;

  const ruleTasks = useMemo(
    () =>
      createRuleTasks({
        idle: () => workRef.current === "idle",
        setWork: (next) => {
          workRef.current = next;
          setWork(next);
        },
        cancelBackend: () => commands.cancelParse(),
        notice: setNotice,
      }),
    [],
  );
  const cancelRule = ruleTasks.cancel;
  const cancelSearch = ruleTasks.cancelSearch;

  /// The `started` channel a rule command fires once it holds the slot.
  const startedChannel = (started: () => void) => {
    const channel = new Channel<null>();
    channel.onmessage = started;
    return channel;
  };
  const evaluateRule = useCallback(
    (id: string, ruleId: string) =>
      ruleTasks.run(async (started) => {
        const result = await commands.evaluateRule(id, ruleId, startedChannel(started));
        if (result.status === "error") throw new Error(result.error);
        return result.data;
      }),
    [ruleTasks],
  );
  const countRuleMatches = useCallback(
    (id: string, source: string) =>
      ruleTasks.run(async (started) => {
        const result = await commands.countRuleMatches(id, source, startedChannel(started));
        if (result.status === "error") throw new Error(result.error);
        return result.data;
      }),
    [ruleTasks],
  );
  const searchCondition = useCallback(
    (id: string, ruleId: string | null, query: string) =>
      ruleTasks.run(async (started) => {
        const result = await commands.searchCondition(
          id,
          ruleId,
          query,
          startedChannel(started),
        );
        if (result.status === "error") throw new Error(result.error);
        return result.data;
      }, true),
    [ruleTasks],
  );
  // Subscribed for the whole app lifetime, not per screen: progress must keep
  // arriving while the user browses another screen.
  useEffect(() => {
    const stops: Array<() => void> = [];
    // Each listener ignores events from the other operation: a late parse
    // event must not overwrite a detection bar, and vice versa.
    void events.detectProgress
      .listen((e) => {
        if (workRef.current !== "detecting") return;
        setProgress({
          done: e.payload.done,
          total: e.payload.total,
          records: 0,
          cancelRequested: false,
        });
      })
      .then((s) => stops.push(s));
    void events.parseProgress
      .listen((e) => {
        if (workRef.current !== "parsing") return;
        setProgress((current) => ({
          done: Math.max(current?.done ?? 0, e.payload.files_done),
          total: e.payload.files_total,
          records: Math.max(current?.records ?? 0, e.payload.records_parsed),
          cancelRequested:
            (current?.cancelRequested ?? false) || e.payload.cancel_requested,
        }));
      })
      .then((s) => stops.push(s));
    return () => stops.forEach((s) => s());
  }, []);

  const refreshCases = useCallback(() => {
    commands.listCases().then((r) => {
      if (r.status === "ok") setCases(r.data);
    });
  }, []);

  useEffect(refreshCases, [refreshCases]);

  // The defaults live in Rust so the UI never hard-codes AWS paths.
  const resetMapping = useCallback(async () => {
    setMapping(await commands.defaultMapping());
  }, []);

  useEffect(() => {
    void resetMapping();
  }, [resetMapping]);

  const chooseDirectory = useCallback(async () => {
    if (workRef.current !== "idle") return;
    const picked = await open({ directory: true, multiple: false });
    if (typeof picked !== "string") return;

    const run = ++runRef.current;
    setNotice(null);
    setRoot(picked);
    setRows([]);
    setSelected(new Set());
    setSummary(null);
    setParsed(null);
    setWork("scanning");

    const scanned = await commands.scanDirectory(picked);
    if (run !== runRef.current) return;
    if (scanned.status === "error") {
      setNotice(scanned.error);
      setWork("idle");
      return;
    }
    setSummary(scanned.data);

    setWork("detecting");
    setProgress({
      done: 0,
      total: scanned.data.candidate_count,
      records: 0,
      cancelRequested: false,
    });
    const detected = await commands.detectLogs(picked);
    if (run !== runRef.current) return;
    if (detected.status === "error") {
      setNotice(detected.error);
      setWork("idle");
      return;
    }
    setRows(detected.data);
    // Every format backed by a parser starts selected; detection-only formats
    // remain visible but cannot enter a parse run.
    setSelected(
      new Set(
        detected.data
          .filter((row) => isParseableLogType(row.log_type))
          .map((row) => row.display_path),
      ),
    );
    setProgress(null);
    setWork("idle");
  }, []);

  // FR-5: parsing starts only on an explicit click, never during detection.
  const startParse = useCallback(async () => {
    if (!root || selected.size === 0 || workRef.current !== "idle") return;
    const run = ++runRef.current;
    setNotice(null);
    setParsed(null);
    setProgress({
      done: 0,
      total: selected.size,
      records: 0,
      cancelRequested: false,
    });
    setWork("parsing");
    setScreen("parsing");

    const result = await commands.startParse(root, [...selected], mapping);
    if (run !== runRef.current) return;
    setWork("idle");
    setProgress(null);
    if (result.status === "error") {
      setNotice(result.error);
      return;
    }
    setParsed(result.data);
    setCaseId(result.data.case_id);
    refreshCases();
  }, [root, selected, mapping, refreshCases]);

  const value = useMemo<State>(
    () => ({
      screen,
      work,
      root,
      summary,
      rows,
      selected,
      progress,
      parsed,
      caseId,
      cases,
      notice,
      mapping,
      setMapping,
      resetMapping,
      go: (next) => {
        if (next === "results" && workRef.current === "cancelling-rule") return;
        if (next !== "results") void cancelRule();
        setScreen(next);
      },
      openCase: (id: string) => {
        if (workRef.current === "cancelling-rule") return;
        if (id !== caseId) void cancelRule();
        setCaseId(id);
        setScreen("results");
      },
      setNotice,
      deleteCase: async (id: string) => {
        // A parse holds the store open; on Windows that fails the recursive
        // delete and leaves a half-removed directory behind.
        if (workRef.current !== "idle")
          return setNotice("작업 중에는 케이스를 삭제할 수 없습니다");
        const r = await commands.deleteCase(id);
        if (r.status === "error") return setNotice(r.error);
        // Every route back into the deleted case has to go, or "결과 보기"
        // opens a database that is no longer there.
        if (caseId === id) {
          setCaseId(null);
          setScreen((current) => (current === "results" ? "start" : current));
        }
        setParsed((current) => (current?.case_id === id ? null : current));
        refreshCases();
      },
      toggle: (displayPath: string) =>
        setSelected((prev) => {
          const next = new Set(prev);
          if (!next.delete(displayPath)) next.add(displayPath);
          return next;
        }),
      setSelected,
      chooseDirectory,
      startParse,
      evaluateRule,
      countRuleMatches,
      searchCondition,
      cancelSearch,
      cancelRule,
      cancelParse: () => {
        void commands.cancelParse();
        setProgress((p) => (p ? { ...p, cancelRequested: true } : p));
      },
      reset: () => {
        if (workRef.current !== "idle" && workRef.current !== "evaluating") return;
        runRef.current += 1;
        setRoot(null);
        setSummary(null);
        setRows([]);
        setSelected(new Set());
        setParsed(null);
        setProgress(null);
        setWork("idle");
        setScreen("start");
        void cancelRule();
      },
    }),
    [
      screen,
      work,
      root,
      summary,
      rows,
      selected,
      progress,
      parsed,
      caseId,
      cases,
      notice,
      mapping,
      resetMapping,
      chooseDirectory,
      startParse,
      refreshCases,
      evaluateRule,
      countRuleMatches,
      searchCondition,
      cancelSearch,
      cancelRule,
    ],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
