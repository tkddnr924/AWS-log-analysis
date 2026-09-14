import { useEffect, useState } from "react";

import { StatStrip } from "./StatStrip";
import { useApp } from "../state";

function formatElapsed(seconds: number) {
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return minutes > 0 ? `${minutes}분 ${rest}초` : `${rest}초`;
}

/// Step 2: the parse run. Finishing does not jump anywhere on its own — the
/// analyst chooses to open the results or to start another directory.
export function ParsingPanel() {
  const { work, progress, parsed, caseId, go, openCase, reset, cancelParse } =
    useApp();
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (work !== "parsing") {
      setElapsed(0);
      return;
    }
    const started = Date.now();
    const tick = () => setElapsed(Math.floor((Date.now() - started) / 1000));
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [work]);

  if (work === "parsing") {
    const pct =
      progress && progress.total > 0
        ? Math.round((progress.done / progress.total) * 100)
        : 0;
    const done = progress?.done ?? 0;
    const total = progress?.total ?? 0;
    return (
      <div className="parse-card" role="status" aria-live="polite">
        <div className="parse-head">
          <h1>파싱 중</h1>
          <span className="parse-pct">{pct}%</span>
        </div>
        <div className="bar parse-bar">
          <div className="bar-fill" style={{ width: `${pct}%` }} />
        </div>
        <dl className="parse-stats">
          <div>
            <dt>파일</dt>
            <dd>
              <strong>{done.toLocaleString()}</strong>
              <small> / {total.toLocaleString()}</small>
            </dd>
          </div>
          <div>
            <dt>레코드</dt>
            <dd>
              <strong>{(progress?.records ?? 0).toLocaleString()}</strong>
            </dd>
          </div>
          <div>
            <dt>경과</dt>
            <dd>
              <strong>{formatElapsed(elapsed)}</strong>
            </dd>
          </div>
        </dl>
        <p className="parse-actions">
          <button
            className="danger"
            onClick={cancelParse}
            disabled={progress?.cancelRequested}
          >
            {progress?.cancelRequested ? "취소 중" : "취소"}
          </button>
          {/* The run keeps going; the dock brings the user back. */}
          <button onClick={() => go("start")}>시작 화면</button>
        </p>
      </div>
    );
  }

  if (!parsed) {
    return (
      <div className="parse-card">
        <div className="parse-head">
          <h1>파싱이 끝나지 않았습니다</h1>
        </div>
        <p className="parse-actions">
          <button onClick={() => go("start")}>시작 화면으로</button>
        </p>
      </div>
    );
  }

  return (
    <div className="parse-card">
      <div className="parse-head">
        <h1>{parsed.cancelled ? "파싱 취소됨" : "파싱 완료"}</h1>
      </div>
      <p className="case-ref">
        케이스 <code>{parsed.case_id}</code>
      </p>

      {/* Zero rows are omitted: a "실패 0" card is noise, not reassurance. */}
      <StatStrip
        stats={[
          { label: "레코드", value: parsed.records_parsed, unit: "개" },
          { label: "파싱한 파일", value: parsed.files_parsed, unit: "개" },
          ...(parsed.files_failed > 0
            ? [
                {
                  label: "실패한 파일",
                  value: parsed.files_failed,
                  unit: "개",
                  tone: "danger" as const,
                },
              ]
            : []),
          ...(parsed.files_skipped > 0
            ? [
                {
                  label: "제외된 파일",
                  value: parsed.files_skipped,
                  unit: "개",
                },
              ]
            : []),
        ]}
      />

      <p className="parse-actions">
        <button onClick={reset}>새 로그 가져오기</button>
        <button
          className="primary"
          onClick={() => openCase(caseId ?? parsed.case_id)}
        >
          결과 보기
        </button>
      </p>
    </div>
  );
}
