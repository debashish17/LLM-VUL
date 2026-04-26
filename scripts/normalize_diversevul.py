"""
Normalize DiverseVul dataset to unified schema.

Input:  data/raw/diversevul.json (large ~700MB)
Output: data/normalized/diversevul.jsonl

Schema mapping:
  - func             → code
  - target           → label_binary
  - cwe (list)       → label_cwe (take first if list, else null)
  - message          → extract CVE (regex: CVE-XXXX-XXXXX)
  - language         → hardcoded to "c"
"""

import ijson
import json
import os
import re
from pathlib import Path
from collections import defaultdict

def extract_cve_from_message(message):
    """Extract CVE ID from message using regex pattern CVE-XXXX-XXXXX."""
    if not message:
        return None
    # Pattern: CVE-YYYY-NNNNN (where Y=year digits, N=number digits)
    match = re.search(r'CVE-\d{4}-\d{4,5}', str(message))
    return match.group(0) if match else None

def normalize_diversevul(input_path, output_path):
    """Normalize DiverseVul dataset to unified schema."""
    
    print("=" * 80)
    print("NORMALIZING DIVERSEVUL DATASET")
    print("=" * 80)
    
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    stats = defaultdict(int)
    
    try:
        # Stream parse large JSON file
        print(f"\n[1] Streaming raw dataset: {input_path}")
        
        normalized_records = []
        record_id = 0
        
        with open(input_path, 'rb') as f:
            # Use ijson to stream-parse JSON
            parser = ijson.items(f, '', multiple_values=True)
            
            for raw_rec in parser:
                if not isinstance(raw_rec, dict):
                    continue
                
                try:
                    # Extract and validate code
                    code = raw_rec.get('func', '').strip()
                    
                    if not code:
                        stats['skipped_empty_code'] += 1
                        continue
                    
                    # Convert label (should be int 0 or 1)
                    target = raw_rec.get('target')
                    label_binary = int(target) if target is not None else 0
                    
                    # Handle CWE (list → take first, or null)
                    cwe = raw_rec.get('cwe')
                    if isinstance(cwe, list):
                        label_cwe = cwe[0] if cwe else None
                    else:
                        label_cwe = cwe
                    
                    # Extract CVE from message
                    message = raw_rec.get('message', '')
                    label_cve = extract_cve_from_message(message)
                    
                    # Build normalized record (language hardcoded to "c")
                    normalized_rec = {
                        "id": f"diversevul_{record_id}",
                        "dataset": "diversevul",
                        "language": "c",
                        "code": code,
                        "label_binary": label_binary,
                        "label_cwe": label_cwe,
                        "label_cve": label_cve,
                    }
                    
                    normalized_records.append(normalized_rec)
                    record_id += 1
                    stats['success'] += 1
                    
                    # Progress indicator
                    if stats['success'] % 50000 == 0:
                        print(f"  ✓ Processed {stats['success']:,} records...")
                
                except Exception as e:
                    stats['error'] += 1
                    if stats['error'] <= 3:
                        print(f"  [WARN] Record error: {e}")
                    continue
        
        print(f"  ✓ Stream processing complete")
        print(f"\n[2] Saving to {output_path}...")
        
        # Save as JSONL
        with open(output_path, 'w', encoding='utf-8') as f:
            for rec in normalized_records:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        
        file_size = Path(output_path).stat().st_size / (1024*1024)
        print(f"  ✓ Wrote {len(normalized_records):,} records")
        print(f"  ✓ File size: {file_size:.2f} MB")
        
        # Statistics
        print(f"\n[3] Processing Statistics:")
        print(f"  • Success: {stats['success']:,}")
        for key in sorted(stats.keys()):
            if key != 'success':
                print(f"  • {key}: {stats[key]}")
        
        # Label distribution
        print(f"\n[4] Label Distribution:")
        label_counts = defaultdict(int)
        for rec in normalized_records:
            label_counts[rec['label_binary']] += 1
        
        for label in sorted(label_counts.keys()):
            count = label_counts[label]
            pct = 100 * count / len(normalized_records)
            label_name = "Vulnerable" if label == 1 else "Safe"
            print(f"  • {label_name} ({label}): {count:,} ({pct:.1f}%)")
        
        # Language distribution
        print(f"\n[5] Language Distribution:")
        lang_counts = defaultdict(int)
        for rec in normalized_records:
            lang_counts[rec['language']] += 1
        
        for lang in sorted(lang_counts.keys()):
            count = lang_counts[lang]
            pct = 100 * count / len(normalized_records)
            print(f"  • {lang.upper()}: {count:,} ({pct:.1f}%)")
        
        print(f"\n{'='*80}")
        print(f"✅ DiverseVul normalization complete!")
        print(f"   Output: {Path(output_path).absolute()}")
        print(f"{'='*80}\n")
        
        return len(normalized_records)
    
    except Exception as e:
        print(f"[ERROR] Normalization failed: {e}")
        import traceback
        traceback.print_exc()
        return 0

if __name__ == "__main__":
    input_file = "data/raw/diversevul.json"
    output_file = "data/normalized/diversevul.jsonl"
    
    normalize_diversevul(input_file, output_file)
