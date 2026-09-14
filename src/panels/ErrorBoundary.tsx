import { Component, type ErrorInfo, type ReactNode } from "react";

type Props = { label: string; resetKey: string; children: ReactNode };
type State = { error: Error | null };

/// Isolates a render failure to one screen so the shell, navigation and any
/// running parse stay usable.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidUpdate(prev: Props) {
    // Moving to another screen or case clears the failure.
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Component stack only: log records must never reach the console.
    console.error(`${this.props.label} 렌더 실패`, error.message, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="boundary">
        <p className="error">
          {this.props.label}을(를) 표시하지 못했습니다 — {error.message}
        </p>
        <button onClick={() => this.setState({ error: null })}>다시 시도</button>
      </div>
    );
  }
}
