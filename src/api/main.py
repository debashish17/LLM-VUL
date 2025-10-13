"""Minimal CLI entrypoint for scanning a file."""

import argparse
from src.parser.code_parser import parse_code
from src.detector.model import VulnerabilityModel


def main():
    parser = argparse.ArgumentParser(description="Scan a source file for simple issues")
    parser.add_argument("path", help="Path to the source file to scan")
    args = parser.parse_args()

    parsed = parse_code(args.path)
    model = VulnerabilityModel()
    issues = model.predict(parsed)

    print(f"Scanned: {args.path}")
    if not issues:
        print("No issues found.")
    else:
        for it in issues:
            print(f"Line {it['line']}: {it['severity']} {it['cwe']} - {it['message']}")


if __name__ == '__main__':
    main()
