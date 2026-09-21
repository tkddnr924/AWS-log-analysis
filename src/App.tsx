import { Results } from "./Results";
import { ErrorBoundary } from "./panels/ErrorBoundary";
import { ParsingPanel } from "./panels/ParsingPanel";
import { StartPanel } from "./panels/StartPanel";
import { AppStateProvider, useApp, type Screen } from "./state";

const SCREEN_LABELS: Record<Screen, string> = {
  start: "시작 화면",
  parsing: "파싱 화면",
  results: "결과 화면",
};

export function App() {
  return (
    <AppStateProvider>
      <Shell />
    </AppStateProvider>
  );
}

function Shell() {
  const { screen, work, progress, caseId, notice, setNotice, go, cancelParse } = useApp();

  return (
    <div className="shell">
      {notice && (
        <div className="notice" role="alert" aria-live="assertive">
          <span>{notice}</span>
          <button className="linklike" onClick={() => setNotice(null)}>
            닫기
          </button>
        </div>
      )}

      <main className="panel">
        <ErrorBoundary label={SCREEN_LABELS[screen]} resetKey={`${screen}:${caseId ?? ""}`}>
          {screen === "start" && <StartPanel />}
          {screen === "parsing" && <ParsingPanel />}
          {screen === "results" && caseId && <Results key={caseId} caseId={caseId} />}
        </ErrorBoundary>
      </main>

      {/* Floating dock, since there is no bar to live in any more: a running
          parse must stay visible and cancellable from every screen. */}
      {work === "parsing" && screen !== "parsing" && (
        <div className="work-dock" role="status" aria-live="polite">
          <button className="linklike" onClick={() => go("parsing")}>
            파싱 중 · {progress?.done ?? 0}/{progress?.total ?? 0} 파일
          </button>
          <button onClick={cancelParse} disabled={progress?.cancelRequested}>
            {progress?.cancelRequested ? "취소 중" : "취소"}
          </button>
        </div>
      )}
      {work === "cancelling-rule" && (
        <div className="work-dock" role="status" aria-live="polite">
          룰 평가 중단 중…
        </div>
      )}
    </div>
  );
}
