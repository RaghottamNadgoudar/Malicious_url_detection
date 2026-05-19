"""
Test the trained model with known safe and malicious URLs
"""

from phase3_neural_classifier import NeuralClassifier
from phase1_graph_traversal import RedirectGraphAnalyzer
from phase2_pattern_matching import PatternMatcher

# Initialize
classifier = NeuralClassifier()
graph_analyzer = RedirectGraphAnalyzer()
pattern_matcher = PatternMatcher()

# Test URLs
test_urls = {
    'safe': [
        'https://www.google.com',
        'https://www.facebook.com',
        'https://www.amazon.com',
        'https://www.microsoft.com',
        'https://www.github.com',
    ],
    'malicious': [
        'http://malware-site.tk',
        'http://phishing-login.ml',
        'http://192.168.1.1/admin',
        'http://bit.ly/xyz123abc',
        'http://suspicious-site.xyz/login?redirect=http://evil.com',
    ]
}

print("=" * 70)
print("MODEL TESTING - Known Safe vs Malicious URLs")
print("=" * 70)

for category, urls in test_urls.items():
    print(f"\n{category.upper()} URLs:")
    print("-" * 70)
    
    for url in urls:
        # Analyze
        phase1 = graph_analyzer.analyze_url(url)
        phase2 = pattern_matcher.analyze_url(url)
        result = classifier.analyze_url(url, phase1, phase2)
        
        prob = result['threat_probability']
        verdict = result['verdict']
        
        # Color coding
        if category == 'safe' and prob > 0.5:
            status = "❌ WRONG"
        elif category == 'malicious' and prob < 0.5:
            status = "❌ WRONG"
        else:
            status = "✓ CORRECT"
        
        print(f"{status} | {url[:50]:50s} | {prob:.1%} | {verdict}")

print("\n" + "=" * 70)
