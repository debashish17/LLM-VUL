import json
import os

def check_normalized(path, required_fields):
    print(f"\nChecking: {path}")
    if not os.path.exists(path):
        print("  [ERROR] File not found.")
        return

    count = 0
    missing = {field: 0 for field in required_fields}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            count += 1
            rec = json.loads(line)
            for field in required_fields:
                if field not in rec or rec[field] is None:
                    missing[field] += 1
            if count == 1:
                print("  Sample record:", rec)
    print(f"  Total records: {count}")
    for field, miss in missing.items():
        if miss > 0:
            print(f"  Missing {field}: {miss}")
    if all(miss == 0 for miss in missing.values()):
        print("  [OK] All required fields present.")

if __name__ == "__main__":
    devign_fields = [
        "id", "dataset", "language", "file_path", "code", "label_type", "label_binary"
    ]
    zenodo_fields = [
        "id", "dataset", "language", "file_path", "code", "label_type", "label_binary", "label_cwe"
    ]
    check_normalized("normalized/devign.jsonl", devign_fields)
    check_normalized("normalized/zenodo.jsonl", zenodo_fields)