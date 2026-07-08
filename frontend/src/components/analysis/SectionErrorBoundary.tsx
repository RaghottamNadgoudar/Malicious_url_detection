import { Component, type ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';

interface Props {
  children: ReactNode;
  sectionName?: string;
}

interface State {
  hasError: boolean;
  errorMessage: string;
}

/**
 * ErrorBoundary that prevents a single section crash from blanking the whole page.
 * Renders a compact error card in place of the crashed section.
 */
export default class SectionErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, errorMessage: '' };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, errorMessage: error.message };
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    console.error(`[SectionErrorBoundary] Section "${this.props.sectionName}" crashed:`, error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="border border-red-500/20 bg-red-950/10 rounded-2xl p-6 flex items-start gap-4 font-mono text-xs">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <span className="text-red-400 font-bold block mb-1 uppercase tracking-wider">
              {this.props.sectionName ?? 'Section'} — Render Error
            </span>
            <p className="text-slate-400 leading-relaxed">
              This analysis panel encountered a runtime error and could not render.
              All other phases and the final verdict are unaffected.
            </p>
            {this.state.errorMessage && (
              <code className="block mt-2 text-[10px] text-red-300 bg-[#0c1322] border border-red-900/40 rounded px-3 py-1.5">
                {this.state.errorMessage}
              </code>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
