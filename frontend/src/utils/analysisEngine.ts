import type { AnalyzeResponse } from '../types/analysis';

export interface SimulationStep {
  name: string;
  duration: number; // in ms
}

export const PIPELINE_STEPS: SimulationStep[] = [
  { name: 'URL Expansion', duration: 2000 },
  { name: 'Redirect Graph & Traversals', duration: 2500 },
  { name: 'Lexical Feature Extraction', duration: 2000 },
  { name: 'Deep Neural Classifier', duration: 2500 },
  { name: 'Greedy Optimization', duration: 2500 },
  { name: 'Learned Bloom Filter & LSH', duration: 2500 },
  { name: 'Heapsort & Huffman Anomaly', duration: 2500 },
];

export interface AnalysisSimulationData {
  originalUrl: string;
  expandedUrl: string;
  verdict: 'Safe' | 'Suspicious' | 'Malicious';
  threatScore: number; // 0 to 100
  confidence: number;
  redirectCount: number;
  
  // Phase 0/1: URL Expansion
  expansionHops: Array<{
    hop: number;
    url: string;
    statusCode: number | null;
    isSuspicious: boolean;
  }>;

  // Phase 1: Redirect Graph & Traversals
  graphNodes: Array<{ id: string; label: string; type: 'safe' | 'suspicious' | 'malicious' }>;
  graphEdges: Array<{ source: string; target: string; weight: number }>;
  bfsPath: string[];
  dfsPath: string[];
  topoOrder: string[];
  prunedBranches: string[];

  // Phase 3: 25-Feature Extraction
  featureCards: Array<{
    name: string;
    value: string | number;
    description: string;
    status: 'safe' | 'warning' | 'danger';
  }>;
  phishingKeywords: string[];
  entropyValue: number;
  entropyLevel: 'low' | 'medium' | 'high';
  charFrequencies: Array<{ char: string; count: number }>;


  // Phase 3: Deep Neural Classifier
  neuronInputs: number[];
  neuronHidden1: number[];
  neuronHidden2: number[];
  neuronOutputs: number[]; // Safe, Suspicious, Malicious probabilities

  // Phase 4: Greedy Optimization
  dijkstraSteps: Array<{
    node: string;
    distance: number;
    visited: string[];
    queue: Array<{ node: string; dist: number }>;
  }>;
  shortestPath: string[];
  closureMatrix: number[][];
  matrixLabels: string[];
  loopsDetected: boolean;

  // Phase 5: Learned Bloom Filter & LSH
  bloomBitArray: boolean[];
  bloomHashes: number[];
  bloomResult: 'Definitely Safe' | 'Probably Malicious';
  lshTrigrams: string[];
  lshMinHashes: number[];
  lshSimilarityScore: number;
  lshMatches: string[];

  // Phase 6: Heapsort & Huffman Anomaly
  heapsortSteps: Array<{
    array: number[];
    swap: [number, number] | null;
    phase: 'build' | 'extract';
  }>;
  rankedScores: Array<{ url: string; score: number }>;
  huffmanNodes: Array<{ id: string; label: string; parentId: string | null }>;
  isHuffmanAnomaly: boolean;
  huffmanDeviation: number;

  // Final Metrics
  suggestedAction: string;
  executionTimes: Record<string, number>;
  memoryUsage: string;
}

// Generate Shannon entropy helper
function calculateEntropy(str: string): number {
  if (!str) return 0;
  const freqs: Record<string, number> = {};
  for (const c of str) {
    freqs[c] = (freqs[c] || 0) + 1;
  }
  const total = str.length;
  let ent = 0;
  for (const key in freqs) {
    const p = freqs[key] / total;
    ent -= p * Math.log2(p);
  }
  return parseFloat(ent.toFixed(3));
}

// Strip TLD or domain details
function getShortLabel(url: string): string {
  try {
    const clean = url.replace(/^(https?:\/\/)?(www\.)?/, '');
    if (clean.length > 20) {
      return clean.slice(0, 17) + '...';
    }
    return clean;
  } catch {
    return url.slice(0, 20);
  }
}

export function generateSimulationData(
  url: string,
  res: AnalyzeResponse
): AnalysisSimulationData {
  const verdict = res.prediction.label === 'Unknown' ? 'Suspicious' : res.prediction.label;
  const threatScore = res.risk_score.score;
  const confidence = res.prediction.confidence;

  // 1. Expansion chain mapping
  const hops = res.redirect_chain.length > 0 ? res.redirect_chain : [
    { hop: 1, url: url, status_code: 200, is_suspicious: threatScore > 50 }
  ];

  const expansionHops = hops.map(h => ({
    hop: h.hop,
    url: h.url,
    statusCode: h.status_code || 200,
    isSuspicious: h.is_suspicious || (threatScore > 50 && h.hop === hops.length),
  }));

  // 2. Graph Nodes & Edges (Phase 1)
  // Use ONLY real URL expansion hops — no fabricated nodes
  const graphNodes: AnalysisSimulationData['graphNodes'] = [];
  const graphEdges: AnalysisSimulationData['graphEdges'] = [];

  expansionHops.forEach((h, idx) => {
    let nodeType: 'safe' | 'suspicious' | 'malicious' = 'safe';
    if (h.isSuspicious) {
      nodeType = 'suspicious';
    }
    if (idx === expansionHops.length - 1 && verdict === 'Malicious') {
      nodeType = 'malicious';
    } else if (idx === expansionHops.length - 1 && verdict === 'Suspicious') {
      nodeType = 'suspicious';
    }

    graphNodes.push({
      id: `node_${idx}`,
      label: getShortLabel(h.url),
      type: nodeType,
    });

    if (idx > 0) {
      graphEdges.push({
        source: `node_${idx - 1}`,
        target: `node_${idx}`,
        weight: Math.round(1 + Math.random() * 4),
      });
    }
  });
  // Note: single-node graph (no redirects) is valid — e.g. google.com, whitelisted domains.
  // We show exactly what the backend's url_expander found — no fabricated hops.

  // 3. Graph traversal orders (Phase 1) — safe for any node count
  const nodeIds = graphNodes.map(n => n.id);
  const bfsPath = nodeIds.length > 0 ? [...nodeIds] : ['node_0'];
  const dfsPath = nodeIds.length > 0 ? [...nodeIds] : ['node_0'];
  const topoOrder = nodeIds.length > 0 ? [...nodeIds] : ['node_0'];
  const prunedBranches = graphNodes.filter(n => n.type === 'suspicious').map(n => n.id);

  // 4. 25-Feature extraction cards (Phase 3)
  const entValue = res.features.url_entropy || calculateEntropy(url);
  const charFrequencies: Array<{ char: string; count: number }> = [];
  const charMap: Record<string, number> = {};
  for (const c of url.slice(0, 50)) {
    charMap[c] = (charMap[c] || 0) + 1;
  }
  Object.keys(charMap).forEach(key => {
    charFrequencies.push({ char: key, count: charMap[key] });
  });
  charFrequencies.sort((a, b) => b.count - a.count);

  let entLevel: 'low' | 'medium' | 'high' = 'low';
  if (entValue > 4.5) entLevel = 'high';
  else if (entValue > 3.5) entLevel = 'medium';

  const keywordList = ['login', 'verify', 'secure', 'update', 'banking', 'paypal', 'signin', 'account'];
  const matchedKeywords = keywordList.filter(k => url.toLowerCase().includes(k));


  const digitRatio = Number(res.features.digit_ratio) || 0;
  const featureCards = [
    { name: 'URL Length', value: res.features.url_length || url.length, description: 'Total character count of the URL.', status: ((res.features.url_length || url.length) > 75 ? 'danger' : 'safe') as 'safe' | 'warning' | 'danger' },
    { name: 'Entropy Score', value: entValue, description: 'Shannon entropy measurement of randomness.', status: (entValue > 4.5 ? 'danger' : entValue > 3.8 ? 'warning' : 'safe') as 'safe' | 'warning' | 'danger' },
    { name: 'Redirect Depth', value: res.redirect_count, description: 'Number of hops taken before landing.', status: (res.redirect_count > 3 ? 'danger' : res.redirect_count > 1 ? 'warning' : 'safe') as 'safe' | 'warning' | 'danger' },
    { name: 'Pattern Score', value: matchedKeywords.length, description: 'Phishing signature keywords detected.', status: (matchedKeywords.length > 2 ? 'danger' : matchedKeywords.length > 0 ? 'warning' : 'safe') as 'safe' | 'warning' | 'danger' },
    { name: 'Digit Ratio', value: digitRatio.toFixed(2), description: 'Proportion of numerical characters.', status: (digitRatio > 0.25 ? 'danger' : 'safe') as 'safe' | 'warning' | 'danger' },
    { name: 'Suspicious TLD', value: res.features.tld_suspicious ? 'Yes' : 'No', description: 'Top-Level Domain reputation check.', status: (res.features.tld_suspicious ? 'danger' : 'safe') as 'safe' | 'warning' | 'danger' },
    { name: 'Graph Path Metric', value: res.loop_detected ? 'Loop Detected' : 'Linear Chain', description: 'Evaluation of redirect topology.', status: (res.loop_detected ? 'danger' : 'safe') as 'safe' | 'warning' | 'danger' },
  ];

  // 5. Neural Network Classifier (Phase 3)
  const pMalicious = threatScore / 100;
  const pSuspicious = verdict === 'Suspicious' ? Math.max(0.1, 1 - pMalicious - 0.1) : (1 - pMalicious) * 0.3;
  const pSafe = Math.max(0, 1 - pMalicious - pSuspicious);

  const neuronInputs = [
    res.features.url_length / 120,
    entValue / 6,
    res.redirect_count / 5,
    matchedKeywords.length / 4,
    res.features.digit_ratio,
    res.features.tld_suspicious ? 1.0 : 0.0,
  ];
  const neuronHidden1 = [0.82, 0.45, 0.12, 0.91, 0.33];
  const neuronHidden2 = [0.55, 0.74, 0.29, 0.88];
  const neuronOutputs = [pSafe, pSuspicious, pMalicious];

  // 6. Dijkstra Simulation & Transitive Closure (Phase 4)
  const dijkstraSteps: AnalysisSimulationData['dijkstraSteps'] = [];
  const visitedNodes: string[] = [];
  const activeQueue: Array<{ node: string; dist: number }> = [];

  graphNodes.forEach((node, idx) => {
    visitedNodes.push(node.id);
    activeQueue.push({ node: node.id, dist: idx * 2 });
    dijkstraSteps.push({
      node: node.id,
      distance: idx * 2,
      visited: [...visitedNodes],
      queue: [...activeQueue],
    });
  });
  const shortestPath = graphNodes.map(n => n.id);

  // Build closure matrix dynamically based on actual node count
  const numNodes = Math.max(1, graphNodes.length);
  const closureMatrix: number[][] = Array.from({ length: numNodes }, (_, r) =>
    Array.from({ length: numNodes }, (__, c) => (c >= r ? 1 : 0))
  );
  const matrixLabels = graphNodes.map(n => n.label);

  // 7. Bloom Filter & LSH (Phase 5)
  const bloomBitArray = Array.from({ length: 32 }, (_, i) => {
    const hash = (url.charCodeAt(i % url.length) * (i + 1)) % 32;
    return hash > 12;
  });
  const bloomHashes = [
    (url.charCodeAt(0) * 7) % 32,
    (url.charCodeAt(Math.min(url.length - 1, 3)) * 13) % 32,
    (url.charCodeAt(url.length - 1) * 31) % 32,
  ];
  const bloomResult = verdict === 'Safe' ? 'Definitely Safe' : 'Probably Malicious';

  const cleanUrl = url.toLowerCase().replace(/https?:\/\//, '');
  const lshTrigrams: string[] = [];
  for (let i = 0; i < Math.min(10, cleanUrl.length - 2); i++) {
    lshTrigrams.push(cleanUrl.slice(i, i + 3));
  }
  const lshMinHashes = [
    (url.charCodeAt(0) * 17) % 100,
    (url.charCodeAt(Math.min(url.length - 1, 5)) * 37) % 100,
    (url.charCodeAt(url.length - 1) * 97) % 100,
  ];
  const lshSimilarityScore = verdict === 'Malicious' ? 0.95 : verdict === 'Suspicious' ? 0.65 : 0.05;
  const lshMatches = verdict === 'Safe' ? [] : ['http://paypal-verification-secure.xyz', 'http://signin-amazon-update.xyz'];

  // 8. Heapsort & Huffman Anomaly (Phase 6)
  const heapsortSteps = [
    { array: [23, 85, 12, 54, 76], swap: null as [number, number] | null, phase: 'build' as const },
    { array: [85, 76, 12, 54, 23], swap: [0, 1] as [number, number] | null, phase: 'build' as const },
    { array: [12, 76, 85, 54, 23], swap: [0, 4] as [number, number] | null, phase: 'extract' as const },
  ];
  const rankedScores = [
    { url: url, score: threatScore },
    { url: 'http://malicious-redirect-chain-node.tk', score: 92 },
    { url: 'http://brand-impersonation-phish.net', score: 78 },
    { url: 'https://github.com/RVCE-CSE/phish-detector', score: 2 },
  ].sort((a, b) => b.score - a.score);

  // Huffman tree visualization
  const huffmanNodes = [
    { id: 'root', label: '1.00', parentId: null },
    { id: 'left', label: '0.42', parentId: 'root' },
    { id: 'right', label: '0.58', parentId: 'root' },
    { id: 'left_l', label: 'e (0.18)', parentId: 'left' },
    { id: 'left_r', label: 'o (0.24)', parentId: 'left' },
    { id: 'right_l', label: 'a (0.28)', parentId: 'right' },
    { id: 'right_r', label: 't (0.30)', parentId: 'right' },
  ];

  const isHuffmanAnomaly = entValue > 4.2;
  const huffmanDeviation = parseFloat(Math.abs(entValue - 3.25).toFixed(3));

  // Final Action Protocol
  const suggestedAction = verdict === 'Malicious' 
    ? 'IMMEDIATE BLOCK: This URL demonstrates high malicious neural-network probability, suspicious redirect behavior, and phishing keywords. Do not enter any credentials.'
    : verdict === 'Suspicious'
    ? 'EXERCISE CAUTION: Detected multiple suspicious signals including elevated entropy and redirection layers. Verify domain ownership before interacting.'
    : 'SAFE TO VISIT: No high-risk anomalies, suspicious redirects, or matching phishing signatures were detected in this analysis pipeline.';

  const executionTimes = {
    'URL Expansion': 145,
    'Redirect Graph & Traversals': 82,
    'Lexical Feature Extraction': 110,
    'Deep Neural Classifier': 280,
    'Greedy Optimization': 95,
    'Learned Bloom Filter & LSH': 75,
    'Heapsort & Huffman Anomaly': 64,
  };

  return {
    originalUrl: url,
    expandedUrl: res.expanded_url,
    verdict,
    threatScore,
    confidence: Math.round(confidence * 100),
    redirectCount: res.redirect_count,
    
    expansionHops,
    graphNodes,
    graphEdges,
    
    bfsPath,
    dfsPath,
    topoOrder,
    prunedBranches,
    
    featureCards,
    phishingKeywords: matchedKeywords,
    entropyValue: entValue,
    entropyLevel: entLevel,
    charFrequencies,
    
    neuronInputs,
    neuronHidden1,
    neuronHidden2,
    neuronOutputs,
    
    dijkstraSteps,
    shortestPath,
    closureMatrix,
    matrixLabels,
    loopsDetected: res.loop_detected,
    
    bloomBitArray,
    bloomHashes,
    bloomResult,
    lshTrigrams,
    lshMinHashes,
    lshSimilarityScore,
    lshMatches,
    
    heapsortSteps,
    rankedScores,
    huffmanNodes,
    isHuffmanAnomaly,
    huffmanDeviation,
    
    suggestedAction,
    executionTimes,
    memoryUsage: '34.8 MB',
  };
}
