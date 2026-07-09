import { Routes, Route } from 'react-router-dom';
import Navbar from './components/shared/Navbar';
import LandingPage from './pages/LandingPage';
import PipelineOneView from './pages/pipeline1/PipelineOneView';
import PipelineTwoView from './pages/pipeline2/PipelineTwoView';
import AnalysisView from './pages/AnalysisView';

export default function App() {
  return (
    <div className="min-h-screen bg-bg-base font-sans">
      <Navbar />
      <main className="pt-16">
        <Routes>
          <Route path="/"          element={<LandingPage />} />
          <Route path="/pipeline1" element={<PipelineOneView />} />
          <Route path="/pipeline2" element={<PipelineTwoView />} />
          <Route path="/analysis"  element={<AnalysisView />} />
        </Routes>
      </main>
    </div>
  );
}
