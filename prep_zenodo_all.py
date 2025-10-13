"""
normalize_zenodo_all.py
-----------------------
Normalize all Zenodo vulnerability dataset files in data/zenodo/ into a unified JSONL format.

Input  : All CSV/JSON/JSONL files in data/zenodo/
Output : normalized/zenodo.jsonl — standardized schema across datasets.
"""

import pandas as pd
import json
import os
from glob import glob
from datetime import datetime

def normalize_zenodo_file(input_path, f_out, start_index=0):
    """Normalize a single Zenodo file and append to output file."""
    print(f"[INFO] Loading dataset: {input_path}")
    if input_path.endswith(".csv"):
        df = pd.read_csv(input_path)
    elif input_path.endswith(".json") or input_path.endswith(".jsonl"):
        df = pd.read_json(input_path, lines=True)
    else:
        print(f"[WARN] Skipped unsupported file: {input_path}")
        return 0

    print(f"[INFO] Loaded {len(df)} records from {input_path}")
    count = 0
    for i, row in df.iterrows():
        try:
            record = {
                "id": f"zenodo_{start_index + i}",
                "dataset": "zenodo",
                "language": str(row.get("programming_language", "")).lower(),
                "file_path": row.get("file_name"),
                "code": row.get("code", ""),
                "context": row.get("commit_msg", ""),
                "label_type": "binary",
                "label_binary": 1 if bool(row.get("is_vulnerable", False)) else 0,
                "label_cwe": row.get("cwe_id"),
                "label_cve": row.get("cve_id"),
                "patch": None,
                "line_from": None,
                "line_to": None,
                "notes": (
                    f"repo_owner={row.get('repo_owner')}, "
                    f"repo_url={row.get('repo_url')}, "
                    f"committer={row.get('committer')}, "
                    f"committer_date={row.get('committer_date')}"
                ),
                "cwe_name": row.get("cwe_name"),
                "cwe_description": row.get("cwe_description"),
                "cwe_url": row.get("cwe_url"),
            }
            f_out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1
        except Exception as e:
            print(f"[WARN] Skipped record {i} in {input_path} due to error: {e}")
    return count

if __name__ == "__main__":
    input_dir = "data/zenodo"
    output_path = "normalized/zenodo.jsonl"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    files = glob(os.path.join(input_dir, "data_*.csv")) + \
            glob(os.path.join(input_dir, "data_*.json")) + \
            glob(os.path.join(input_dir, "data_*.jsonl"))

    print(f"[INFO] Found {len(files)} files: {files}")

    total = 0
    start_time = datetime.now()
    with open(output_path, "w", encoding="utf-8") as f_out:
        for f in files:
            total += normalize_zenodo_file(f, f_out, start_index=total)

    print(f"[✅] Normalization complete! Saved {total} records to: {output_path}")
    print(f"[⏱️] Done in {datetime.now() - start_time}")