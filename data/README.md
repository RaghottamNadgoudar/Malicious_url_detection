# Data Directory

This directory contains the datasets used for training and testing the URL detection system.

## Required Files

### 📊 merged_urls.csv
Combined dataset of malicious and benign URLs.

**Format:**
```csv
url,label,result
https://example.com,benign,0
https://phishing-site.com,phishing,1
```

**Columns:**
- `url`: The URL string
- `label`: Human-readable label (benign/phishing/malware/etc.)
- `result`: Binary classification (0 = benign, 1 = malicious)

### 📊 balanced_urls.csv
Balanced dataset with equal distribution of benign and malicious URLs.

**Format:** Same as merged_urls.csv

**Purpose:** Used for training to prevent class imbalance issues.

## Dataset Statistics

After loading your datasets, you should have:
- **Total URLs:** ~100,000+
- **Benign URLs:** ~50%
- **Malicious URLs:** ~50%

## Usage

The backend automatically loads datasets from this directory:

```python
# In backend/app.py
for dataset_path in ['../data/merged_urls.csv', '../data/balanced_urls.csv']:
    if os.path.exists(dataset_path):
        dataset = pd.read_csv(dataset_path)
```

## Data Sources

Common sources for URL datasets:
- PhishTank (phishing URLs)
- URLhaus (malware URLs)
- Alexa Top Sites (benign URLs)
- Common Crawl (benign URLs)

## Git Ignore

⚠️ **Note:** CSV files are ignored by git due to their large size.

To share datasets:
1. Upload to cloud storage (Google Drive, Dropbox, etc.)
2. Share the download link in project documentation
3. Team members download and place files in this directory

## Data Preprocessing

Before using the datasets:

```bash
cd backend
python data_preprocessing.py
```

This will:
- Clean URLs
- Remove duplicates
- Balance classes
- Extract features
- Save processed data

## File Size Guidelines

- `merged_urls.csv`: ~50-100 MB
- `balanced_urls.csv`: ~30-60 MB

If files are larger, consider:
- Sampling a subset
- Compressing with gzip
- Using Parquet format instead of CSV
