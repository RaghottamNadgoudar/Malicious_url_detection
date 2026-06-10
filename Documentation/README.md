# Documentation

This folder contains all project documentation for the Hybrid URL Detection System.

## Files

### 📚 ALGORITHMS_EXPLAINED.md
Comprehensive explanation of all algorithms used in the system:
- Phase 0: URL Expansion (HTTP Redirect Following)
- Phase 1: Graph Traversal (BFS/DFS, Shannon Entropy, Topological Sort)
- Phase 2: Pattern Matching (Boyer-Moore, Horspool)
- Phase 3: Neural Network (Feedforward with Backpropagation)
- Phase 4: Greedy Optimization (Dijkstra's Algorithm)
- Phase 5: Bloom Filter with LSH
- Phase 6: Heapsort Ranking with Huffman Coding
- Phase 7: Transitive Closure (BFS-based)

Each algorithm includes:
- Code examples
- Complexity analysis
- Visual explanations
- Use cases

### 🔄 WORKFLOW_PIPELINE.md
Highly detailed, end-to-end trace of how a URL is processed by the hybrid engine:
- Visual Mermaid workflow charts
- Step-by-step description of data flows and DAA paradigms
- Verdict blending decision trees
- Subsystem integration details (Backend, React Frontend, Chrome Extension)
- Offline model training & live performance benchmarking flows

### 🧪 TEST_URLS.md
Collection of test URLs for validating the system:
- Safe URLs (legitimate websites)
- Malicious URLs (phishing patterns)
- Suspicious URLs (borderline cases)
- URL Shorteners (bit.ly, tinyurl.com, etc.)
- Edge cases

Use these URLs to test the detection system's accuracy.

## Quick Links

- [Main README](../README.md)
- [Quick Start Guide](../QUICKSTART.md)
- [Project Summary](../PROJECT_SUMMARY.md)
- [Workflow Pipeline](WORKFLOW_PIPELINE.md)

## Contributing

When adding new documentation:
1. Keep it concise and well-structured
2. Include code examples where relevant
3. Add visual diagrams if helpful
4. Update this README with new file descriptions
