import { useState } from 'react';
import type { AnalysisState } from './types/analysis';
import Navbar from './components/Navbar';
import LandingPage from './components/LandingPage';
import ResultsDashboard from './components/ResultsDashboard';
import ThreatDashboard from './components/ThreatDashboard';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import AnalysisDashboard from './pages/AnalysisDashboard';

function HomeView() {
  const [state, setState] = useState<AnalysisState>({ status: 'idle' });
  const [showDashboard, setShowDashboard] = useState(false);

  const handleReset = () => setState({ status: 'idle' });

  return (
    <div className="min-h-screen bg-[#ffffff] text-gray-900">
      <Navbar
        onReset={state.status === 'success' ? handleReset : undefined}
        onDashboard={() => setShowDashboard(v => !v)}
        isDashboard={showDashboard}
      />

      {showDashboard ? (
        <div className="pt-16">
          <ThreatDashboard />
        </div>
      ) : state.status === 'success' ? (
        <div className="pt-16">
          <ResultsDashboard data={state.data} onReset={handleReset} />
        </div>
      ) : (
        <LandingPage onResult={setState} analysisState={state} />
      )}
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomeView />} />
        <Route path="/analysis" element={<AnalysisDashboard />} />
      </Routes>
    </BrowserRouter>
  );
}

