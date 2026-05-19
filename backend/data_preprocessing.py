"""
Data Preprocessing: Merge balanced_urls.csv with dephides dataset
"""

import pandas as pd
import os


def load_balanced_urls(path='../../balanced_urls.csv'):
    """Load the balanced URLs dataset."""
    df = pd.read_csv(path)
    # Schema: url, label, result
    # result: 0 = benign, 1 = malicious
    return df


def load_dephides_data(base_path='../../dephides/dataset/big_dataset'):
    """
    Load dephides dataset.
    Format: <label>\t<url>
    Labels: 'legitimate' or 'phishing'
    """
    datasets = {}
    
    for split in ['test', 'val']:
        file_path = os.path.join(base_path, f'{split}.txt')
        
        if not os.path.exists(file_path):
            print(f"Warning: {file_path} not found")
            continue
        
        urls = []
        labels = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split('\t', 1)
                if len(parts) == 2:
                    label, url = parts
                    labels.append(label.strip())
                    urls.append(url.strip())
        
        df = pd.DataFrame({
            'url': urls,
            'label': labels
        })
        
        # Convert to our schema
        df['label'] = df['label'].map({'legitimate': 'benign', 'phishing': 'malicious'})
        df['result'] = df['label'].map({'benign': 0, 'malicious': 1})
        
        datasets[split] = df
        print(f"Loaded {split}: {len(df)} URLs")
    
    return datasets


def merge_datasets(balanced_df, dephides_datasets, sample_size=50000):
    """
    Merge balanced_urls with dephides data.
    Sample from dephides to avoid overwhelming the original dataset.
    """
    # Start with balanced dataset
    merged = balanced_df.copy()
    
    # Add samples from dephides
    for split_name, df in dephides_datasets.items():
        # Sample equally from benign and malicious
        benign = df[df['result'] == 0].sample(min(sample_size // 2, len(df[df['result'] == 0])))
        malicious = df[df['result'] == 1].sample(min(sample_size // 2, len(df[df['result'] == 1])))
        
        sampled = pd.concat([benign, malicious])
        merged = pd.concat([merged, sampled], ignore_index=True)
        
        print(f"Added {len(sampled)} URLs from {split_name}")
    
    # Remove duplicates
    original_len = len(merged)
    merged = merged.drop_duplicates(subset=['url'], keep='first')
    print(f"Removed {original_len - len(merged)} duplicates")
    
    # Shuffle
    merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return merged


def save_merged_dataset(df, output_path='../../merged_urls.csv'):
    """Save merged dataset."""
    df.to_csv(output_path, index=False)
    print(f"\nSaved merged dataset: {len(df)} URLs")
    print(f"  Benign: {len(df[df['result'] == 0])}")
    print(f"  Malicious: {len(df[df['result'] == 1])}")
    print(f"  Output: {output_path}")


if __name__ == '__main__':
    print("=" * 60)
    print("Data Preprocessing: Merging Datasets")
    print("=" * 60)
    
    # Load datasets
    print("\n1. Loading balanced_urls.csv...")
    balanced_df = load_balanced_urls()
    print(f"   Loaded: {len(balanced_df)} URLs")
    
    print("\n2. Loading dephides dataset...")
    dephides_datasets = load_dephides_data()
    
    print("\n3. Merging datasets...")
    merged_df = merge_datasets(balanced_df, dephides_datasets, sample_size=100000)
    
    print("\n4. Saving merged dataset...")
    save_merged_dataset(merged_df)
    
    print("\n" + "=" * 60)
    print("✓ Data preprocessing complete!")
    print("=" * 60)
