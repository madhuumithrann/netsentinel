import { Component } from 'react';
import { AlertTriangle } from 'lucide-react';

/**
 * Keeps a rendering bug in one view from blanking the whole app: the analysis result
 * stays in memory and the other views keep working. Reset by changing `resetKey`.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidUpdate(prev) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="error-box" role="alert">
        <AlertTriangle size={18} aria-hidden="true" />
        <div className="stack" style={{ '--gap': '6px' }}>
          <strong>This view could not be displayed</strong>
          <span className="text-2">
            The analysis result is still loaded; the other views are unaffected. Try another view, or download the JSON
            report from the bar above.
          </span>
          <span className="mono xs muted">{String(this.state.error?.message || this.state.error).slice(0, 300)}</span>
        </div>
      </div>
    );
  }
}
