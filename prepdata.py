import pandas as pd
import json
import os

# Load Devign JSON
with open("data/devign/data/raw/dataset.json", "r", encoding="utf-8") as f:
    data = json.load(f)
df = pd.DataFrame(data)

out_path = "normalized/devign.jsonl"
os.makedirs(os.path.dirname(out_path), exist_ok=True)

records = []
for _, row in df.iterrows():
    rec = {
        "id": f"devign_{row['commit_id']}",
        "dataset": "devign",
        "language": "c",               # Devign is C/C++
        "file_path": f"{row['project']}/{row['commit_id']}.c",
        "code": row['func'],
        "context": "",
        "label_type": "binary",
        "label_binary": int(row['target']),
        "label_cwe": None,
        "patch": None,
        "line_from": None,
        "line_to": None,
        "notes": row['project']
    }
    records.append(rec)

with open(out_path, "w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r) + "\n")

print(f"Wrote {len(records)} records to {out_path}")