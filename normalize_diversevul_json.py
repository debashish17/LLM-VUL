"""
normalize_diversevul_json.py
----------------------------
Normalize DiverseVul (RAID 2023) dataset variant with fields:
['func', 'target', 'cwe', 'project', 'commit_id', 'hash', 'size', 'message']

Output: normalises/diversevul.jsonl
Language is inferred from project name and code content.
"""

import ijson
import json
import os
from datetime import datetime
from tqdm import tqdm
from pygments.lexers import guess_lexer
from pygments.util import ClassNotFound

# --- 1️⃣ Expanded Project → Language mapping ---
PROJECT_LANG_MAP = {
    # C projects
    "ffmpeg": "c", "openssl": "c", "linux": "c", "qemu": "c", "curl": "c",
    "libtiff": "c", "gnutls": "c", "libjpeg": "c", "libxml2": "c",
    "imagemagick": "c", "openssh": "c", "glibc": "c", "zlib": "c", "bash": "c",
    "sqlite": "c", "libpng": "c",

    # C++ projects
    "chromium": "cpp", "v8": "cpp", "llvm": "cpp", "clang": "cpp",
    "qt": "cpp", "opencv": "cpp", "boost": "cpp",

    # Python projects
    "pillow": "python", "python-pillow": "python", "numpy": "python",
    "tensorflow": "python", "pytorch": "python", "scikit-learn": "python",
    "flask": "python", "django": "python", "scipy": "python", "requests": "python",
    "django-rest-framework": "python",

    # PHP projects
    "php-src": "php", "phpmyadmin": "php", "joomla": "php", "wordpress": "php",
    "laravel": "php", "magento": "php", "drupal": "php",

    # Java projects
    "spring-framework": "java", "hadoop": "java", "elasticsearch": "java"
}

# --- 2️⃣ Helper functions ---
def infer_language_from_project(project: str) -> str:
    """Infer programming language from project name"""
    if not project:
        return "unknown"
    p = project.lower()
    for key, lang in PROJECT_LANG_MAP.items():
        if key in p:
            return lang
    return "unknown"

def infer_language_from_code(code: str) -> str:
    """Infer programming language from code snippet using Pygments"""
    if not code.strip():
        return "unknown"
    try:
        lexer = guess_lexer(code)
        lang = lexer.name.lower()
        if "c++" in lang or "cpp" in lang:
            return "cpp"
        if "c" in lang:
            return "c"
        if "python" in lang:
            return "python"
        if "php" in lang:
            return "php"
        if "java" in lang:
            return "java"
        return "unknown"
    except ClassNotFound:
        return "unknown"

# --- 3️⃣ Main normalization ---
def normalize_diversevul_json(input_path: str):
    output_path = os.path.join("normalized", "diversevul.jsonl")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print(f"[INFO] Normalizing DiverseVul dataset: {input_path}")
    total, unknown = 0, 0

    with open(input_path, "rb") as f_in, open(output_path, "w", encoding="utf-8") as f_out:
        items = ijson.items(f_in, "", multiple_values=True)

        for row in tqdm(items, desc="Processing records"):
            if not isinstance(row, dict):
                continue
            try:
                project = row.get("project")
                code_snippet = row.get("func", "")

                # 1️⃣ Try project-based detection
                language = infer_language_from_project(project)

                # 2️⃣ Fallback to code-based detection
                if language == "unknown":
                    language = infer_language_from_code(code_snippet)
                    if language == "unknown":
                        unknown += 1

                record = {
                    "id": f"diversevul_{row.get('hash', row.get('commit_id', total))}",
                    "dataset": "diversevul",
                    "language": language,
                    "file_path": None,
                    "code": code_snippet,
                    "context": row.get("message", ""),
                    "label_type": "binary",
                    "label_binary": int(row.get("target", 0)),
                    "label_cwe": row.get("cwe"),
                    "label_cve": None,
                    "patch": None,
                    "notes": f"project={project}, commit={row.get('commit_id')}"
                }

                f_out.write(json.dumps(record, ensure_ascii=False) + "\n")
                total += 1

            except Exception as e:
                print(f"[WARN] Skipped record {total} due to error: {e}")
                continue

    print(f"\n[✅] Saved {total} normalized records to: {output_path}")
    print(f"[ℹ️] Unknown language count: {unknown}")
    print("[📁] Location:", os.path.abspath(output_path))

# --- 4️⃣ CLI ---
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Normalize DiverseVul dataset with language detection")
    parser.add_argument("--input", required=True, help="Path to DiverseVul JSON file")
    args = parser.parse_args()

    start = datetime.now()
    normalize_diversevul_json(args.input)
    print(f"[⏱️] Completed in {datetime.now() - start}")
