import { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Shield, RefreshCw, ChevronLeft } from 'lucide-react';
import { analyzeUrl } from '../services/api';
import { generateSimulationData, PIPELINE_STEPS } from '../utils/analysisEngine';
import type { AnalysisSimulationData } from '../utils/analysisEngine';

import PipelineHeader from '../components/analysis/PipelineHeader';
import URLExpansionSection from '../components/analysis/URLExpansionSection';
import RedirectGraphSection from '../components/analysis/RedirectGraphSection';
import GraphAlgorithmsSection from '../components/analysis/GraphAlgorithmsSection';
import EntropySection from '../components/analysis/EntropySection';
import FeatureExtractionSection from '../components/analysis/FeatureExtractionSection';
import NeuralNetworkSection from '../components/analysis/NeuralNetworkSection';
import DijkstraSection from '../components/analysis/DijkstraSection';
import BloomFilterSection from '../components/analysis/BloomFilterSection';
import HeapsortSection from '../components/analysis/HeapsortSection';
import TransitiveClosureSection from '../components/analysis/TransitiveClosureSection';
import FinalReportSection from '../components/analysis/FinalReportSection';
import RightSidebar from '../components/analysis/RightSidebar';
import BottomAnalytics from '../components/analysis/BottomAnalytics';
import SectionErrorBoundary from '../components/analysis/SectionErrorBoundary';

export default function AnalysisDashboard() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const targetUrl = searchParams.get('url') || '';

  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [errorMsg, setErrorMsg] = useState('');
  const [simData, setSimData] = useState<AnalysisSimulationData | null>(null);
  const [currentPhaseIndex, setCurrentPhaseIndex] = useState(-1);

  // Trigger analysis call
  useEffect(() => {
    if (!targetUrl) {
      navigate('/');
      return;
    }

    async function runAnalysis() {
      setStatus('loading');
      setCurrentPhaseIndex(-1);
      setErrorMsg('');
      try {
        const res = await analyzeUrl({ url: targetUrl, follow_redirects: true });
        const generated = generateSimulationData(targetUrl, res);
        setSimData(generated);
        
        // Start sequential pipeline animation unlocking
        let phase = 0;
        setCurrentPhaseIndex(0);
        
        const runNextPhase = () => {
          if (phase < PIPELINE_STEPS.length - 1) {
            const currentDuration = PIPELINE_STEPS[phase].duration;
            setTimeout(() => {
              phase += 1;
              setCurrentPhaseIndex(phase);
              runNextPhase();
            }, currentDuration);
          } else {
            // All phases completed
            setTimeout(() => {
              setStatus('success');
            }, 1000);
          }
        };

        runNextPhase();

      } catch (err: any) {
        const message = err?.response?.data?.detail || err?.message || 'Threat scan failed.';
        setErrorMsg(message);
        setStatus('error');
      }
    }

    runAnalysis();
  }, [targetUrl, navigate]);

  const handleBackToScanner = () => {
    navigate('/');
  };

  // Render helpers for visual stages checks
  const isUnlocked = (idx: number) => {
    return currentPhaseIndex >= idx || status === 'success';
  };

  const isActive = (idx: number) => {
    return currentPhaseIndex === idx && status === 'loading';
  };

  const isDone = (idx: number) => {
    return currentPhaseIndex > idx || status === 'success';
  };

  return (
    <div className="min-h-screen bg-[#070d1a] text-slate-100 flex flex-col font-sans">
      {/* Top dashboard header bar */}
      <header className="fixed top-0 left-0 right-0 h-16 bg-[#0c1322]/90 backdrop-blur-md border-b border-[#1a2740] flex items-center px-6 justify-between z-50">
        <div className="flex items-center gap-3">
          <button 
            onClick={handleBackToScanner}
            className="flex items-center gap-1.5 px-3 py-1.5 hover:bg-[#1a2740] rounded-lg text-slate-400 hover:text-white transition-all text-xs font-mono font-bold"
          >
            <ChevronLeft size={14} /> Back
          </button>
          <div className="w-px h-5 bg-[#1a2740]" />
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 bg-blue-600 rounded-lg flex items-center justify-center">
              <Shield size={14} className="text-white" />
            </div>
            <span className="font-mono font-black text-sm tracking-tight">
              HYBRID PIPELINE SECURITY ANALYZER
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {status === 'error' && (
            <button 
              onClick={() => window.location.reload()}
              className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-700 text-white font-mono font-bold text-xs px-3.5 py-2 rounded-lg transition-all"
            >
              <RefreshCw size={12} /> Retry Scan
            </button>
          )}
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-500/10 border border-green-500/20 text-green-400 text-[10px] font-mono font-black animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
            LIVE SECURITY THREAT LEVEL SYSTEM ACTIVE
          </span>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 pt-24 px-4 md:px-6 lg:px-8 pb-16 max-w-7xl mx-auto w-full flex flex-col lg:flex-row gap-6 relative">
        {status === 'error' ? (
          <div className="flex-1 flex flex-col items-center justify-center py-20 bg-[#0c1322] border border-red-500/20 rounded-2xl p-8 max-w-lg mx-auto self-center text-center space-y-4">
            <div className="text-4xl">⚡</div>
            <h2 className="text-lg font-mono font-bold text-red-400">ANALYSIS DEPLOYMENT FAILED</h2>
            <p className="text-sm text-slate-400 font-mono leading-relaxed">{errorMsg}</p>
            <code className="block text-[11px] bg-[#070d1a] border border-[#1e2e4a] rounded-lg px-4 py-2 font-mono text-blue-400">
              Check Python Flask backend connection on Port 5000.
            </code>
            <button 
              onClick={handleBackToScanner}
              className="inline-flex items-center gap-2 bg-[#1a2740] hover:bg-[#25375c] text-white text-xs font-mono font-bold px-6 py-2.5 rounded-xl transition-all"
            >
              Return to scanner card
            </button>
          </div>
        ) : (
          <>
            {/* Left Content Column */}
            <div className="flex-1 min-w-0 space-y-6">
              {/* Top Header Card */}
              <PipelineHeader
                url={targetUrl}
                status={status}
                currentPhaseIndex={currentPhaseIndex}
                threatScore={simData?.threatScore || 0}
                verdict={simData?.verdict || 'Suspicious'}
              />

              {/* Sequential algorithm sections */}
              {simData && (
                <>
                  {isUnlocked(0) && (
                    <SectionErrorBoundary sectionName="URL Expansion">
                      <URLExpansionSection
                        data={simData}
                        active={isActive(0)}
                        done={isDone(0)}
                      />
                    </SectionErrorBoundary>
                  )}

                  {isUnlocked(1) && (
                    <>
                      <SectionErrorBoundary sectionName="Redirect Graph">
                        <RedirectGraphSection
                          data={simData}
                          active={isActive(1)}
                          done={isDone(1)}
                        />
                      </SectionErrorBoundary>
                      <SectionErrorBoundary sectionName="Graph Algorithms">
                        <GraphAlgorithmsSection
                          data={simData}
                          active={isActive(1)}
                          done={isDone(1)}
                        />
                      </SectionErrorBoundary>
                    </>
                  )}

                  {isUnlocked(2) && (
                    <>
                      <SectionErrorBoundary sectionName="Feature Extraction">
                        <FeatureExtractionSection
                          data={simData}
                          active={isActive(2)}
                          done={isDone(2)}
                        />
                      </SectionErrorBoundary>
                      <SectionErrorBoundary sectionName="Shannon Entropy">
                        <EntropySection
                          data={simData}
                          active={isActive(2)}
                          done={isDone(2)}
                        />
                      </SectionErrorBoundary>
                    </>
                  )}

                  {isUnlocked(3) && (
                    <SectionErrorBoundary sectionName="Neural Classifier">
                      <NeuralNetworkSection
                        data={simData}
                        active={isActive(3)}
                        done={isDone(3)}
                      />
                    </SectionErrorBoundary>
                  )}

                  {isUnlocked(4) && (
                    <>
                      <SectionErrorBoundary sectionName="Dijkstra Analysis">
                        <DijkstraSection
                          data={simData}
                          active={isActive(4)}
                          done={isDone(4)}
                        />
                      </SectionErrorBoundary>
                      <SectionErrorBoundary sectionName="Transitive Closure">
                        <TransitiveClosureSection
                          data={simData}
                          active={isActive(4)}
                          done={isDone(4)}
                        />
                      </SectionErrorBoundary>
                    </>
                  )}

                  {isUnlocked(5) && (
                    <SectionErrorBoundary sectionName="Bloom Filter">
                      <BloomFilterSection
                        data={simData}
                        active={isActive(5)}
                        done={isDone(5)}
                      />
                    </SectionErrorBoundary>
                  )}

                  {isUnlocked(6) && (
                    <SectionErrorBoundary sectionName="Heapsort Ranking">
                      <HeapsortSection
                        data={simData}
                        active={isActive(6)}
                        done={isDone(6)}
                      />
                    </SectionErrorBoundary>
                  )}

                  {status === 'success' && (
                    <SectionErrorBoundary sectionName="Final Report">
                      <FinalReportSection
                        data={simData}
                        active={false}
                        done={true}
                      />
                    </SectionErrorBoundary>
                  )}


                  {/* Bottom charts diagnostics panel */}
                  <SectionErrorBoundary sectionName="Bottom Analytics">
                    <BottomAnalytics
                      data={simData}
                      active={status === 'success' || currentPhaseIndex >= 0}
                      done={status === 'success'}
                    />
                  </SectionErrorBoundary>
                </>
              )}
            </div>

            {/* Right Sticky Sidebar Column */}
            <RightSidebar
              data={simData}
              currentPhaseIndex={currentPhaseIndex}
              status={status}
            />
          </>
        )}
      </main>
    </div>
  );
}
