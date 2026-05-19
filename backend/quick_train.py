"""
Quick Training Script - Train model with ALL 830K URLs
"""

print("=" * 60)
print("Neural Network Training - Full Dataset")
print("=" * 60)
print("\n📊 Dataset: 830,011 URLs (merged)")
print("⏱️  Estimated time: 20-40 minutes")
print("🧠 Model: 15 → 64 → 32 → 1 (TensorFlow)")
print("=" * 60)
print("\nStarting training...\n")

# Import training functions
from train_model import load_data, extract_all_features, train_and_evaluate

# Execute training
print("=" * 60)
print("URL Detection Model Training")
print("=" * 60)

# Load data
print("\n[1/4] Loading dataset...")
df = load_data(sample_size=None)  # Use ALL URLs

# Extract features
print("\n[2/4] Extracting features from URLs...")
print("This will take 15-30 minutes for 830K URLs...")
X, y = extract_all_features(df, max_urls=None)

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
