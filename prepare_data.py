import pandas as pd
import json
from pathlib import Path
from sklearn.model_selection import train_test_split

print('📊 Preparing Devign dataset for training...')

# Load data
with open('data/devign/data.json', 'r') as f:
    data = json.load(f)

df = pd.DataFrame(data)
print(f'Loaded: {len(df)} samples')
print(f'Columns: {list(df.columns)}')

# Check target distribution
if 'target' in df.columns:
    vuln_count = df['target'].sum()
    safe_count = (df['target'] == 0).sum()
    print(f'\nVulnerable: {vuln_count}')
    print(f'Safe: {safe_count}')
elif 'label' in df.columns:
    df = df.rename(columns={'label': 'target'})
    vuln_count = df['target'].sum()
    safe_count = (df['target'] == 0).sum()
    print(f'\nVulnerable: {vuln_count}')
    print(f'Safe: {safe_count}')

# Clean data
print('\n🧹 Cleaning data...')
original_size = len(df)
df = df.drop_duplicates(subset=['func'])
df = df[df['func'].str.strip() != '']
removed = original_size - len(df)
print(f'After cleaning: {len(df)} samples ({removed} removed)')

# Balance dataset (take 10k of each for quick training)
print('\n⚖️ Balancing dataset...')
vuln_df = df[df['target'] == 1]
safe_df = df[df['target'] == 0]

n_vuln = min(10000, len(vuln_df))
n_safe = min(10000, len(safe_df))

vulnerable = vuln_df.sample(n=n_vuln, random_state=42)
safe = safe_df.sample(n=n_safe, random_state=42)
df_balanced = pd.concat([vulnerable, safe]).sample(frac=1, random_state=42)

total = len(df_balanced)
vuln_balanced = int(df_balanced['target'].sum())
safe_balanced = int((df_balanced['target'] == 0).sum())

print(f'Balanced dataset: {total} samples')
print(f'  Vulnerable: {vuln_balanced}')
print(f'  Safe: {safe_balanced}')

# Create splits
print('\n🔀 Creating train/val/test splits...')
train, temp = train_test_split(
    df_balanced, 
    test_size=0.3, 
    random_state=42, 
    stratify=df_balanced['target']
)
val, test = train_test_split(
    temp, 
    test_size=0.5, 
    random_state=42, 
    stratify=temp['target']
)

print(f'Train: {len(train)} samples')
print(f'Val:   {len(val)} samples')
print(f'Test:  {len(test)} samples')

# Save processed data
Path('data/processed').mkdir(exist_ok=True, parents=True)
train.to_pickle('data/processed/train.pkl')
val.to_pickle('data/processed/val.pkl')
test.to_pickle('data/processed/test.pkl')

# Also save as JSON for easy inspection
train.to_json('data/processed/train.json', orient='records', lines=True)
val.to_json('data/processed/val.json', orient='records', lines=True)
test.to_json('data/processed/test.json', orient='records', lines=True)

print('\n✅ Data preparation complete!')
print(f'   Saved to: data/processed/')
print(f"\nYou can now start training with:")
print(f"   jupyter lab  # Create training notebook")
print(f"   OR")
print(f"   python train_model.py  # If you have training script")
