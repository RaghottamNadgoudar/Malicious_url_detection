import { useState } from 'react';
import type { AnalysisState } from './types/analysis';
import Navbar from './components/Navbar';
import LandingPage from './components/LandingPage';
import ResultsDashboard from './components/ResultsDashboard';

export default function App() {
  const [state, setState] = useState<AnalysisState>({ status: 'idle' });

  const handleReset = () => setState({ status: 'idle' });

  return (
    <div className="min-h-screen bg-white text-gray-900">
      {/* Persistent navbar — transparent over hero, white on scroll */}
      <Navbar onReset={state.status === 'success' ? handleReset : undefined} />

      {/* Page content */}
      {state.status === 'success' ? (
        /* Results view */
        <div className="pt-16">
          <ResultsDashboard data={state.data} onReset={handleReset} />
        </div>
      ) : (
        /* Landing page (handles its own padding/layout) */
        <LandingPage onResult={setState} analysisState={state} />
      )}
    </div>
  );
}
