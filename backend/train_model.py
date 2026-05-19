"""
Train the Neural Network Model
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns
import os

from phase1_graph_traversal import RedirectGraphAnalyzer
from phase2_pattern_matching import PatternMatcher
from phase3_neural_classifier import extract_features, NeuralClassifier


def load_data(data_path='../../merged_urls.csv', sample_size=None):
    """Load and optionally sample the dataset."""
    print(f"Loading data from {data_path}...")
    
    if not os.path.exists(data_path):
        print(f"Merged dataset not found. Using balanced_urls.csv...")
        data_path = '../../balanced_urls.csv'
    
    df = pd.read_csv(data_path)
    
    if sample_size and len(df) > sample_size:
        df = df.sample(sample_size, random_state=42)
        print(f"Sampled {sample_size} URLs from {len(df)} total")
    
    print(f"✓ Loaded {len(df)} URLs")
    print(f"  Benign: {len(df[df['result'] == 0])} ({len(df[df['result'] == 0])/len(df)*100:.1f}%)")
    print(f"  Malicious: {len(df[df['result'] == 1])} ({len(df[df['result'] == 1])/len(df)*100:.1f}%)")
    
    return df


def extract_all_features(df, max_urls=None):
    """Extract features for all URLs in the dataset."""
    print("\nExtracting features...")
    
    # Initialize analyzers
    print("  Initializing analyzers...")
    graph_analyzer = RedirectGraphAnalyzer()
    pattern_matcher = PatternMatcher()
    
    # Build graph from sample
    print("  Building redirect graph...")
    sample_urls = df['url'].tolist()[:min(10000, len(df))]
    graph_analyzer.build_graph(sample_urls)
    print(f"  ✓ Graph built with {len(graph_analyzer.graph)} nodes")
    
    features_list = []
    labels = []
    
    urls_to_process = df['url'].tolist()
    if max_urls:
        urls_to_process = urls_to_process[:max_urls]
    
    print(f"\n  Processing {len(urls_to_process)} URLs...")
    print("  Progress: ", end='', flush=True)
    
    for idx, (url, label) in enumerate(zip(urls_to_process, df['result'].tolist()[:len(urls_to_process)])):
        # Progress bar
        if idx % 1000 == 0:
            progress = (idx / len(urls_to_process)) * 100
            print(f"\r  Progress: {progress:.1f}% ({idx}/{len(urls_to_process)})", end='', flush=True)
        
        try:
            # Phase 1 analysis
            phase1_data = graph_analyzer.analyze_url(url)
            
            # Phase 2 analysis
            phase2_data = pattern_matcher.analyze_url(url)
            
            # Extract features
            features = extract_features(url, phase1_data, phase2_data)
            
            features_list.append(features)
            labels.append(label)
        
        except Exception as e:
            # Skip problematic URLs
            continue
    
    print(f"\r  Progress: 100.0% ({len(urls_to_process)}/{len(urls_to_process)})")
    
    X = np.array(features_list)
    y = np.array(labels)
    
    print(f"\n✓ Extracted features for {len(X)} URLs")
    print(f"  Feature shape: {X.shape}")
    
    return X, y


def train_and_evaluate(X, y, model_dir='models'):
    """Train and evaluate the neural network."""
    print("\n" + "=" * 60)
    print("Training Neural Network")
    print("=" * 60)
    
    # Create model directory
    os.makedirs(model_dir, exist_ok=True)
    
    # Split data: 70% train, 15% val, 15% test
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.176, random_state=42, stratify=y_temp  # 0.176 * 0.85 ≈ 0.15
    )
    
    print(f"\nDataset split:")
    print(f"  Train: {len(X_train)} samples")
    print(f"  Val:   {len(X_val)} samples")
    print(f"  Test:  {len(X_test)} samples")
    
    # Initialize classifier
    model_path = os.path.join(model_dir, 'url_classifier.h5')
    classifier = NeuralClassifier(model_path=model_path)
    
    # Train
    print("\nTraining model...")
    history = classifier.train(
        X_train, y_train,
        X_val, y_val,
        epochs=50,
        batch_size=256
    )
    
    # Evaluate on test set
    print("\n" + "=" * 60)
    print("Evaluation on Test Set")
    print("=" * 60)
    
    y_pred_prob = []
    for i in range(0, len(X_test), 1000):
        batch = X_test[i:i+1000]
        batch_pred = [classifier.classifier.predict(x) for x in batch]
        y_pred_prob.extend(batch_pred)
    
    y_pred_prob = np.array(y_pred_prob)
    y_pred = (y_pred_prob > 0.5).astype(int)
    
    # Metrics
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    auc_score = roc_auc_score(y_test, y_pred_prob)
    print(f"\nAUC-ROC Score: {auc_score:.4f}")
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign', 'Malicious'],
                yticklabels=['Benign', 'Malicious'])
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(os.path.join(model_dir, 'confusion_matrix.png'))
    print(f"\n✓ Saved confusion matrix to {model_dir}/confusion_matrix.png")
    
    # Plot training history
    if hasattr(history, 'history'):
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        
        # Accuracy
        ax1.plot(history.history['accuracy'], label='Train Accuracy')
        ax1.plot(history.history['val_accuracy'], label='Val Accuracy')
        ax1.set_title('Model Accuracy')
        ax1.set_xlabel('Epoch')
        ax1.set_ylabel('Accuracy')
        ax1.legend()
        ax1.grid(True)
        
        # Loss
        ax2.plot(history.history['loss'], label='Train Loss')
        ax2.plot(history.history['val_loss'], label='Val Loss')
        ax2.set_title('Model Loss')
        ax2.set_xlabel('Epoch')
        ax2.set_ylabel('Loss')
        ax2.legend()
        ax2.grid(True)
        
        plt.tight_layout()
        plt.savefig(os.path.join(model_dir, 'training_history.png'))
        print(f"✓ Saved training history to {model_dir}/training_history.png")
    
    return classifier, history, auc_score


if __name__ == '__main__':
    print("=" * 60)
    print("URL Detection Model Training")
    print("=" * 60)
    
    # Load data
    print("\n[1/4] Loading dataset...")
    df = load_data(sample_size=None)  # Use ALL URLs (830K)
    
    # Extract features
    print("\n[2/4] Extracting features from URLs...")
    print("This will take 15-30 minutes for 830K URLs...")
    X, y = extract_all_features(df, max_urls=None)  # Process ALL URLs
    
    # Train and evaluate
    print("\n[3/4] Training neural network...")
    classifier, history, auc_score = train_and_evaluate(X, y)
    
    print("\n[4/4] Saving results...")
    print("\n" + "=" * 60)
    print("✓ Training Complete!")
    print(f"  Final AUC-ROC: {auc_score:.4f}")
    print(f"  Model saved to: models/url_classifier.h5")
    print("=" * 60)
    print("\nYou can now start the Flask server:")
    print("  python3 app.py")
    print("=" * 60)
