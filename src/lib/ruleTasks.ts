/// One rule scan at a time — an evaluation, a draft count or a condition
/// search — matching the single slot the backend holds for them. Kept out
/// of React so the ordering rules below can be exercised on their own.
///
/// A search is only a view of the case: any later request replaces a
/// running one. Several requests can be waiting on the same cancellation;
/// only the newest search among them may start, or the user would see the
/// results of a query they already typed past.

/// Thrown to a search that a newer request replaced before it started.
export class SupersededError extends Error {
  constructor() {
    super("검색이 새 검색으로 바뀌었습니다");
  }
}

export type RuleTaskHost = {
  /// Nothing else (parse, detection, a rule scan) is using the app.
  idle: () => boolean;
  setWork: (work: "evaluating" | "cancelling-rule" | "idle") => void;
  /// Asks the backend to stop the scan holding its slot.
  cancelBackend: () => Promise<unknown>;
  notice: (message: string) => void;
};

type Task = {
  started: Promise<void>;
  finished: Promise<void>;
  done: boolean;
  stopping?: Promise<void>;
  search: boolean;
};

export function createRuleTasks(host: RuleTaskHost) {
  let current: Task | null = null;
  // Bumped by every request and by `cancelSearch`; a search still waiting
  // when it moved on was replaced.
  let generation = 0;

  function cancel(): Promise<void> {
    const task = current;
    if (!task) return Promise.resolve();
    if (task.stopping) return task.stopping;
    host.setWork("cancelling-rule");
    task.stopping = (async () => {
      try {
        // Cancellation must not arrive before the backend claims its slot.
        await Promise.race([task.started, task.finished]);
        if (!task.done) await host.cancelBackend();
      } catch (error) {
        host.notice(String(error));
      } finally {
        // The acknowledgement only sets a flag; the worker still owns the DB.
        await task.finished;
        host.setWork("idle");
      }
    })();
    return task.stopping;
  }

  /// `start` receives the signal to fire once the backend holds its slot.
  async function run<T>(
    start: (started: () => void) => Promise<T>,
    search = false,
  ): Promise<T> {
    const ticket = ++generation;
    if (current?.search) await cancel();
    if (search && ticket !== generation) throw new SupersededError();
    if (!host.idle() || current) {
      throw new Error("다른 작업이 진행 중입니다");
    }
    let markStarted = () => {};
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    host.setWork("evaluating");
    const response = start(markStarted);
    const task: Task = { started, finished: Promise.resolve(), done: false, search };
    const finish = () => {
      task.done = true;
      if (current !== task) return;
      current = null;
      if (!task.stopping) host.setWork("idle");
    };
    task.finished = response.then(finish, finish);
    current = task;
    return response;
  }

  /// Drops the search: a running one is cancelled, a waiting one will not
  /// start. An evaluation or count is left alone.
  async function cancelSearch(): Promise<void> {
    generation += 1;
    if (current?.search) await cancel();
  }

  return { run, cancel, cancelSearch };
}
