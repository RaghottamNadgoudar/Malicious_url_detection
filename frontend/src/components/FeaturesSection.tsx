import {
  Network, GitBranch, AlignLeft, BarChart2, Brain,
  Navigation, Filter, ArrowUpDown, Share2,
  ChevronRight
} from 'lucide-react';

const FEATURES = [
  {
    icon: <Network size={22} />,
    title: 'URL Expansion & Redirect Analysis',
    description: 'Automatically unfolds shortened URLs, follows redirect chains up to 10 hops deep, and detects redirect loops using BFS traversal.',
    tag: 'Graph Theory',
    color: 'blue',
  },
  {
    icon: <GitBranch size={22} />,
    title: 'BFS & DFS Graph Traversal',
    description: 'Models URL redirect graphs using Breadth-First and Depth-First Search to map complete threat propagation paths.',
    tag: 'DAA Algorithm',
    color: 'indigo',
  },
  {
    icon: <AlignLeft size={22} />,
    title: 'Boyer-Moore & Horspool Matching',
    description: 'Applies classical string pattern matching to identify phishing keywords, brand impersonation, and suspicious substrings at O(n/m) efficiency.',
    tag: 'String Algorithms',
    color: 'violet',
  },
  {
    icon: <BarChart2 size={22} />,
    title: 'Shannon Entropy Analysis',
    description: 'Computes information entropy of URLs and domains to detect obfuscated, randomly generated, or algorithmically constructed phishing links.',
    tag: 'Information Theory',
    color: 'sky',
  },
  {
    icon: <Brain size={22} />,
    title: 'Neural Network Classification',
    description: 'A trained ML model evaluates 25 extracted URL features to classify threats as Safe, Suspicious, or Malicious with confidence scoring.',
    tag: 'Machine Learning',
    color: 'purple',
  },
  {
    icon: <Navigation size={22} />,
    title: 'Dijkstra Threat Path Detection',
    description: "Applies Dijkstra's shortest path algorithm on weighted threat graphs to identify the most critical attack vectors within redirect chains.",
    tag: 'DAA Algorithm',
    color: 'blue',
  },
  {
    icon: <Filter size={22} />,
    title: 'Bloom Filter Lookup Engine',
    description: 'Space-efficient probabilistic data structure for sub-millisecond known-threat URL lookups against a database of millions of flagged domains.',
    tag: 'Data Structure',
    color: 'teal',
  },
  {
    icon: <ArrowUpDown size={22} />,
    title: 'Heapsort Threat Ranking',
    description: 'Ranks multiple scanned URLs by composite threat score using a max-heap structure, enabling priority-based security alert triage.',
    tag: 'Sorting Algorithm',
    color: 'amber',
  },
  {
    icon: <Share2 size={22} />,
    title: 'Transitive Closure Analysis',
    description: "Computes Warshall's transitive closure on URL redirect graphs to discover indirect threat relationships and hidden attack chains.",
    tag: 'Graph Algorithm',
    color: 'rose',
  },
];

const COLOR_MAP: Record<string, { icon: string; tag: string; border: string; tagBg: string }> = {
  blue:   { icon: 'text-blue-600',   tag: 'text-blue-700',   border: 'hover:border-blue-200',   tagBg: 'bg-blue-50 text-blue-700 border-blue-100' },
  indigo: { icon: 'text-indigo-600', tag: 'text-indigo-700', border: 'hover:border-indigo-200', tagBg: 'bg-indigo-50 text-indigo-700 border-indigo-100' },
  violet: { icon: 'text-violet-600', tag: 'text-violet-700', border: 'hover:border-violet-200', tagBg: 'bg-violet-50 text-violet-700 border-violet-100' },
  sky:    { icon: 'text-sky-600',    tag: 'text-sky-700',    border: 'hover:border-sky-200',    tagBg: 'bg-sky-50 text-sky-700 border-sky-100' },
  purple: { icon: 'text-purple-600', tag: 'text-purple-700', border: 'hover:border-purple-200', tagBg: 'bg-purple-50 text-purple-700 border-purple-100' },
  teal:   { icon: 'text-teal-600',   tag: 'text-teal-700',   border: 'hover:border-teal-200',   tagBg: 'bg-teal-50 text-teal-700 border-teal-100' },
  amber:  { icon: 'text-amber-600',  tag: 'text-amber-700',  border: 'hover:border-amber-200',  tagBg: 'bg-amber-50 text-amber-700 border-amber-100' },
  rose:   { icon: 'text-rose-600',   tag: 'text-rose-700',   border: 'hover:border-rose-200',   tagBg: 'bg-rose-50 text-rose-700 border-rose-100' },
};

export default function FeaturesSection() {
  return (
    <section id="features" className="py-24 bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <span className="inline-block text-xs font-semibold tracking-widest uppercase text-blue-600 mb-3 px-3 py-1 bg-blue-50 rounded-full border border-blue-100">
            Detection Engine
          </span>
          <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 mb-4">
            9 Algorithms Working in Concert
          </h2>
          <p className="text-lg text-gray-500 max-w-2xl mx-auto">
            A hybrid detection architecture combining classical Design & Analysis of Algorithms with modern machine learning for multi-layer threat intelligence.
          </p>
        </div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {FEATURES.map((feature, idx) => {
            const c = COLOR_MAP[feature.color] || COLOR_MAP.blue;
            return (
              <div
                key={idx}
                className={`group bg-white rounded-xl border border-gray-150 p-6 card-hover cursor-default ${c.border}`}
                style={{ animationDelay: `${idx * 60}ms` }}
              >
                {/* Icon + Tag row */}
                <div className="flex items-start justify-between mb-4">
                  <div className={`w-10 h-10 rounded-lg bg-gray-50 border border-gray-100 flex items-center justify-center ${c.icon} group-hover:scale-110 transition-transform duration-200`}>
                    {feature.icon}
                  </div>
                  <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${c.tagBg}`}>
                    {feature.tag}
                  </span>
                </div>

                {/* Content */}
                <h3 className="font-semibold text-gray-900 text-sm mb-2 leading-snug">
                  {feature.title}
                </h3>
                <p className="text-sm text-gray-500 leading-relaxed">
                  {feature.description}
                </p>

                {/* Bottom hover cue */}
                <div className={`mt-4 flex items-center gap-1 text-xs font-medium opacity-0 group-hover:opacity-100 transition-opacity duration-200 ${c.icon}`}>
                  <span>Learn more</span>
                  <ChevronRight size={12} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
