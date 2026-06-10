# Hybrid AI-Driven Malicious URL Detection System

A comprehensive URL detection system that combines **7 algorithmic phases** with **deep learning** to identify malicious URLs with high accuracy.

## 🎯 Overview

This system implements a multi-phase detection pipeline that analyzes URLs through:
- Graph traversal algorithms (BFS/DFS)
- Pattern matching (Boyer-Moore)
- Neural network classification
- Greedy optimization (Dijkstra)
- Bloom filters with LSH
- Heapsort ranking
- Transitive closure analysis

## 🏗️ Architecture

```
┌─────────────┐
│   Phase 0   │  URL Expansion (Shorteners)
└──────┬──────┘
       │
┌──────▼──────┐
│   Phase 1   │  Graph Traversal (BFS/DFS)
└──────┬──────┘
       │
┌──────▼──────┐
│   Phase 2   │  Pattern Matching (Boyer-Moore)
└──────┬──────┘
       │
┌──────▼──────┐
│   Phase 3   │  Neural Network (15→64→32→1)
└──────┬──────┘
       │
┌──────▼──────┐
│   Phase 4   │  Greedy Optimization (Dijkstra)
└──────┬──────┘
       │
┌──────▼──────┐
│   Phase 5   │  Bloom Filter + LSH
└──────┬──────┘
       │
┌──────▼──────┐
│   Phase 6   │  Heapsort Ranking
└──────┬──────┘
       │
┌──────▼──────┐
│   Phase 7   │  Transitive Closure (BFS)
└──────┬──────┘
       │
       ▼
   Final Verdict
```

## 📁 Project Structure

```
url-detection-system/
├── Documentation/              # All documentation
│   ├── ALGORITHMS_EXPLAINED.md # Detailed algorithm explanations
│   ├── WORKFLOW_PIPELINE.md   # Detailed execution trace & pipeline docs
│   ├── TEST_URLS.md           # Test URLs for validation
│   ├── TRAINING_GUIDE.md      # Model training guide
│   └── README.md              # Documentation index
├── backend/                    # Python backend
│   ├── phase1_graph_traversal.py
│   ├── phase2_pattern_matching.py
│   ├── phase3_neural_classifier.py
│   ├── phase4_greedy_optimization.py
│   ├── phase5_bloom_filter.py
│   ├── phase6_heapsort_ranking.py
│   ├── url_expander.py
│   ├── performance_benchmark.py
│   ├── app.py                 # Flask API
│   ├── train_model.py         # Model training
│   └── requirements.txt
├── frontend/                   # React frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── URLAnalyzer.jsx
│   │   │   ├── PerformanceAnalytics.jsx
│   │   │   └── SystemStats.jsx
│   │   └── App.jsx
│   └── package.json
├── data/                       # Datasets (not in git)
│   ├── merged_urls.csv
│   ├── balanced_urls.csv
│   └── README.md
├── .gitignore
├── CHANGES.md                  # Recent changes
└── README.md                   # This file
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Node.js 16+
- 4GB RAM minimum

### Installation

1. **Clone the repository**
```bash
git clone <your-repo-url>
cd url-detection-system
```

2. **Backend Setup**
```bash
cd backend
pip install -r requirements.txt
```

3. **Frontend Setup**
```bash
cd frontend
npm install
```

4. **Add Dataset**
Place your CSV files in the `data/` folder:
- `merged_urls.csv`
- `balanced_urls.csv`

### Running the System

1. **Start Backend**
```bash
cd backend
python app.py
```
Backend runs on `http://localhost:5000`

2. **Start Frontend**
```bash
cd frontend
npm run dev
```
Frontend runs on `http://localhost:5173`

3. **Open Browser**
Navigate to `http://localhost:5173`

## 🧪 Testing

Test with sample URLs:

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

See `Documentation/TEST_URLS.md` for more test cases.

## 🎓 Training the Model

For best accuracy, train the neural network:

```bash
cd backend
python quick_train.py
```

This trains on 10,000 URLs in ~5 minutes. For full training:

```bash
python train_model.py
```

See `Documentation/TRAINING_GUIDE.md` for details.

## 📊 Performance

| Metric | Value |
|--------|-------|
| Accuracy | 92-95% (trained) |
| Throughput | ~60 URLs/sec |
| Avg Latency | ~17ms |
| False Positive Rate | <5% |

## 🔬 Algorithms Used

1. **BFS/DFS** - Graph traversal for redirect chains
2. **Boyer-Moore** - Efficient pattern matching
3. **Neural Network** - Deep learning classification
4. **Dijkstra** - Shortest path to malicious URLs
5. **Bloom Filter** - Fast membership testing
6. **Heapsort** - Threat ranking
7. **Transitive Closure** - Reachability analysis

See `Documentation/ALGORITHMS_EXPLAINED.md` for detailed explanations.

## 🌟 Features

- ✅ Real-time URL analysis
- ✅ URL shortener expansion (bit.ly, tinyurl.com, etc.)
- ✅ Multi-phase detection pipeline
- ✅ Neural network classification
- ✅ Performance benchmarking
- ✅ Interactive web interface
- ✅ Batch URL analysis
- ✅ Detailed threat reports

## 📖 Documentation

- [Algorithms Explained](Documentation/ALGORITHMS_EXPLAINED.md)
- [Workflow Pipeline](Documentation/WORKFLOW_PIPELINE.md)
- [Training Guide](Documentation/TRAINING_GUIDE.md)
- [Test URLs](Documentation/TEST_URLS.md)
- [Recent Changes](CHANGES.md)

## 🛠️ API Endpoints

### Analyze Single URL
```
POST /api/analyze
Body: {"url": "https://example.com"}
```

### Batch Analysis
```
POST /api/batch-analyze
Body: {"urls": ["url1", "url2"], "top_k": 10}
```

### Performance Metrics
```
GET /api/analytics/performance
```

### System Stats
```
GET /api/system/stats
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is for educational purposes.

## 👥 Authors

- Your Name - Initial work

## 🙏 Acknowledgments

- PhishTank for phishing URL dataset
- URLhaus for malware URL dataset
- TensorFlow team for the ML framework

## 📧 Contact

For questions or issues, please open an issue on GitHub.

---

**Note:** This system is designed for educational and research purposes. Always use multiple layers of security in production environments.
