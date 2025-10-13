"""Utility script to scan a file using the project components."""

from src.parser.code_parser import parse_code
from src.detector.model import VulnerabilityModel
from src.utils.cwe_mapping import describe


def scan(path: str) -> None:
    parsed = parse_code(path)
    model = VulnerabilityModel()
    issues = model.predict(parsed)

    print(f"Scan report for: {path}")
    if not issues:
        print("No issues found.")
    else:
        for it in issues:
            print(f"Line {it['line']}: {it['severity']} {it['cwe']} - {describe(it['cwe'])}")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scripts/scan_file.py <path>")
    else:
        scan(sys.argv[1])
