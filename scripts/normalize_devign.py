"""
Normalize Devign dataset to unified schema.

Input:  data/raw/devign.json (27,318 records)
Output: data/normalized/devign.jsonl

Schema mapping:
  - commit_id     → id
  - func          → code
  - target        → label_binary
  - language      → hardcoded to "c"
  - label_cwe     → null (Devign doesn't have CWE)
  - label_cve     → null (Devign doesn't have CVE)
"""

import json
from pathlib import Path
from collections import defaultdict

def normalize_devign(input_path, output_path):
    """Normalize Devign dataset to unified schema."""
    
    print("=" * 80)
    print("NORMALIZING DEVIGN DATASET")
    print("=" * 80)
    
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Load raw JSON
        print(f"\n[1] Loading raw dataset: {input_path}")
        with open(input_path, 'r', encoding='utf-8') as f:
            raw_records = json.load(f)
        
        print(f"  ✓ Loaded {len(raw_records)} raw records")
        
        # Normalize
        print(f"\n[2] Normalizing records...")
        normalized_records = []
        
        for idx, raw_rec in enumerate(raw_records):
            try:
                # Extract and validate code
                code = raw_rec.get('func', '').strip()
                if not code:
                    continue  # Skip empty code
                
                # Get commit_id for unique identifier
                commit_id = raw_rec.get('commit_id', idx)
                
                # Convert label
                target = raw_rec.get('target')
                label_binary = int(target) if target is not None else 0
                
                # Build normalized record
                normalized_rec = {
                    "id": f"devign_{commit_id}",
                    "dataset": "devign",
                    "language": "c",
                    "code": code,
                    "label_binary": label_binary,
                    "label_cwe": None,
                    "label_cve": None,
                }
                
                normalized_records.append(normalized_rec)
            
            except Exception as e:
                if idx < 5:
                    print(f"  [WARN] Record {idx} error: {e}")
                continue
        
        print(f"  ✓ Normalized {len(normalized_records)} records")
        
        # Save as JSONL
        print(f"\n[3] Saving to {output_path}...")
        with open(output_path, 'w', encoding='utf-8') as f:
            for rec in normalized_records:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        
        file_size = Path(output_path).stat().st_size / (1024*1024)
        print(f"  ✓ Wrote {len(normalized_records):,} records")
        print(f"  ✓ File size: {file_size:.2f} MB")
        
        # Statistics
        print(f"\n[4] Label Distribution:")
        label_counts = defaultdict(int)
        for rec in normalized_records:
            label_counts[rec['label_binary']] += 1
        
        for label in sorted(label_counts.keys()):
            count = label_counts[label]
            pct = 100 * count / len(normalized_records)
            label_name = "Vulnerable" if label == 1 else "Safe"
            print(f"  • {label_name} ({label}): {count:,} ({pct:.1f}%)")
        
        print(f"\n[5] Language Distribution:")
        lang_counts = defaultdict(int)
        for rec in normalized_records:
            lang_counts[rec['language']] += 1
        
        for lang in sorted(lang_counts.keys()):
            count = lang_counts[lang]
            pct = 100 * count / len(normalized_records)
            print(f"  • {lang.upper()}: {count:,} ({pct:.1f}%)")
        
        print(f"\n{'='*80}")
        print(f"✅ Devign normalization complete!")
        print(f"   Output: {Path(output_path).absolute()}")
        print(f"{'='*80}\n")
        
        return len(normalized_records)
    
    except Exception as e:
        print(f"[ERROR] Normalization failed: {e}")
        import traceback
        traceback.print_exc()
        return 0

if __name__ == "__main__":
    input_file = "data/raw/devign.json"
    output_file = "data/normalized/devign.jsonl"
    
    normalize_devign(input_file, output_file)
