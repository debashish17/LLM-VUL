"""
Normalize MegaVul dataset to unified schema.

Input:  data/raw/megavul.json (353,873 records, 2.49 GB)
Output: data/normalized/megavul.jsonl

Schema mapping:
  - func             → code
  - is_vul           → label_binary (True → 1, False → 0)
  - cve_id           → label_cve
  - cwe_ids (list)   → label_cwe (take first if list, else null)
  - language         → hardcoded to "c"
"""

import json
from pathlib import Path
from collections import defaultdict

def normalize_megavul(input_path, output_path):
    """Normalize MegaVul dataset to unified schema."""
    
    print("=" * 80)
    print("NORMALIZING MEGAVUL DATASET")
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
                
                # Convert label (True/False → 1/0)
                is_vul = raw_rec.get('is_vul', False)
                label_binary = 1 if is_vul else 0
                
                # Handle CWE (list → take first, or null)
                cwe_ids = raw_rec.get('cwe_ids')
                if isinstance(cwe_ids, list):
                    label_cwe = cwe_ids[0] if cwe_ids else None
                else:
                    label_cwe = cwe_ids
                
                # Get CVE
                label_cve = raw_rec.get('cve_id') or None
                
                # Build normalized record (language hardcoded to "c")
                normalized_rec = {
                    "id": f"megavul_{idx}",
                    "dataset": "megavul",
                    "language": "c",
                    "code": code,
                    "label_binary": label_binary,
                    "label_cwe": label_cwe,
                    "label_cve": label_cve,
                }
                
                normalized_records.append(normalized_rec)
                
                # Progress indicator
                if (idx + 1) % 50000 == 0:
                    print(f"  ✓ Processed {idx + 1:,} records...")
            
            except Exception as e:
                if idx < 5:
                    print(f"  [WARN] Record {idx} error: {e}")
                continue
        
        print(f"  ✓ Normalization complete")
        
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
        
        print(f"\n[6] Optional Fields:")
        cwe_filled = sum(1 for rec in normalized_records if rec.get('label_cwe'))
        cve_filled = sum(1 for rec in normalized_records if rec.get('label_cve'))
        
        cwe_pct = 100 * cwe_filled / len(normalized_records)
        cve_pct = 100 * cve_filled / len(normalized_records)
        print(f"  • label_cwe filled: {cwe_filled:,} ({cwe_pct:.1f}%)")
        print(f"  • label_cve filled: {cve_filled:,} ({cve_pct:.1f}%)")
        
        print(f"\n{'='*80}")
        print(f"✅ MegaVul normalization complete!")
        print(f"   Output: {Path(output_path).absolute()}")
        print(f"{'='*80}\n")
        
        return len(normalized_records)
    
    except Exception as e:
        print(f"[ERROR] Normalization failed: {e}")
        import traceback
        traceback.print_exc()
        return 0

if __name__ == "__main__":
    input_file = "data/raw/megavul.json"
    output_file = "data/normalized/megavul.jsonl"
    
    normalize_megavul(input_file, output_file)
