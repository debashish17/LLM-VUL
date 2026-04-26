"""
Validation script for normalized datasets.

Checks:
1. Schema compliance (all required fields present)
2. Data quality (no empty code, valid labels)
3. Field types (label_binary is int, etc.)
4. Label distribution
5. Language values
6. Missing/null values
"""

import json
import os
from pathlib import Path
from collections import defaultdict

class NormalizedDatasetValidator:
    """Validate normalized JSONL datasets against schema."""
    
    # Required schema
    REQUIRED_FIELDS = ['id', 'dataset', 'language', 'code', 'label_binary', 'label_cwe', 'label_cve']
    VALID_LANGUAGES = ['c', 'cpp']
    VALID_LABELS = [0, 1]
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.stats = {
            'total_records': 0,
            'valid_records': 0,
            'errors': defaultdict(int),
            'warnings': defaultdict(int),
            'label_distribution': defaultdict(int),
            'language_distribution': defaultdict(int),
            'empty_cwe': 0,
            'empty_cve': 0,
        }
    
    def validate(self):
        """Run all validations on the dataset."""
        if not Path(self.file_path).exists():
            print(f"[ERROR] File not found: {self.file_path}")
            return False
        
        print(f"\n{'='*80}")
        print(f"VALIDATING: {Path(self.file_path).name}")
        print(f"{'='*80}")
        
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_no, line in enumerate(f, 1):
                    self._validate_record(line, line_no)
            
            # Print results
            self._print_results()
            
            # Determine if safe
            is_safe = self._is_safe_for_training()
            return is_safe
        
        except Exception as e:
            print(f"[FATAL ERROR] {e}")
            return False
    
    def _validate_record(self, line, line_no):
        """Validate a single record."""
        self.stats['total_records'] += 1
        
        try:
            rec = json.loads(line.strip())
        except json.JSONDecodeError as e:
            self.stats['errors']['json_decode_error'] += 1
            if line_no <= 5:
                print(f"  [ERROR] Line {line_no} invalid JSON: {e}")
            return
        
        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in rec:
                self.stats['errors'][f'missing_field_{field}'] += 1
                return
        
        # Validate code (must be non-empty string)
        code = rec.get('code')
        if not isinstance(code, str) or not code.strip():
            self.stats['errors']['empty_code'] += 1
            return
        
        # Validate label_binary (must be int: 0 or 1)
        label = rec.get('label_binary')
        if not isinstance(label, int) or label not in self.VALID_LABELS:
            self.stats['errors'][f'invalid_label_{label}'] += 1
            return
        
        # Validate language
        language = rec.get('language')
        if language not in self.VALID_LANGUAGES:
            self.stats['warnings'][f'unknown_language_{language}'] += 1
        
        # Check optional fields (can be null)
        cwe = rec.get('label_cwe')
        cve = rec.get('label_cve')
        
        if cwe is None:
            self.stats['empty_cwe'] += 1
        if cve is None:
            self.stats['empty_cve'] += 1
        
        # Track distributions
        self.stats['label_distribution'][label] += 1
        self.stats['language_distribution'][language] += 1
        
        self.stats['valid_records'] += 1
    
    def _print_results(self):
        """Print validation results."""
        print(f"\n[1] Record Count:")
        print(f"  • Total: {self.stats['total_records']:,}")
        print(f"  • Valid: {self.stats['valid_records']:,}")
        print(f"  • Invalid: {self.stats['total_records'] - self.stats['valid_records']:,}")
        
        if self.stats['errors']:
            print(f"\n[2] Errors Found:")
            for error_type, count in sorted(self.stats['errors'].items()):
                print(f"  • {error_type}: {count}")
        else:
            print(f"\n[2] ✓ No errors found")
        
        if self.stats['warnings']:
            print(f"\n[3] Warnings:")
            for warn_type, count in sorted(self.stats['warnings'].items()):
                print(f"  • {warn_type}: {count}")
        else:
            print(f"\n[3] ✓ No warnings")
        
        print(f"\n[4] Label Distribution (in valid records):")
        for label in sorted(self.stats['label_distribution'].keys()):
            count = self.stats['label_distribution'][label]
            if self.stats['valid_records'] > 0:
                pct = 100 * count / self.stats['valid_records']
                label_name = "Vulnerable" if label == 1 else "Safe"
                print(f"  • {label_name} ({label}): {count:,} ({pct:.1f}%)")
        
        print(f"\n[5] Language Distribution (in valid records):")
        for lang in sorted(self.stats['language_distribution'].keys()):
            count = self.stats['language_distribution'][lang]
            if self.stats['valid_records'] > 0:
                pct = 100 * count / self.stats['valid_records']
                print(f"  • {lang.upper()}: {count:,} ({pct:.1f}%)")
        
        print(f"\n[6] Optional Fields:")
        if self.stats['valid_records'] > 0:
            cwe_pct = 100 * (self.stats['valid_records'] - self.stats['empty_cwe']) / self.stats['valid_records']
            cve_pct = 100 * (self.stats['valid_records'] - self.stats['empty_cve']) / self.stats['valid_records']
            print(f"  • label_cwe filled: {self.stats['valid_records'] - self.stats['empty_cwe']:,} ({cwe_pct:.1f}%)")
            print(f"  • label_cve filled: {self.stats['valid_records'] - self.stats['empty_cve']:,} ({cve_pct:.1f}%)")
    
    def _is_safe_for_training(self):
        """Determine if dataset is safe for training."""
        issues = []
        
        # Check 1: All records are valid
        if self.stats['valid_records'] == 0:
            issues.append("No valid records found")
        elif self.stats['valid_records'] < self.stats['total_records']:
            invalid_pct = 100 * (self.stats['total_records'] - self.stats['valid_records']) / self.stats['total_records']
            if invalid_pct > 10:  # If >10% invalid, warn
                issues.append(f"{invalid_pct:.1f}% of records are invalid")
        
        # Check 2: Reasonable class balance (warn if one class is <2%)
        if self.stats['valid_records'] > 0:
            for label, count in self.stats['label_distribution'].items():
                pct = 100 * count / self.stats['valid_records']
                if pct < 2:
                    label_name = "Vulnerable" if label == 1 else "Safe"
                    issues.append(f"Class imbalance: {label_name} is only {pct:.1f}%")
        
        # Check 3: Has valid languages
        if not any(lang in self.VALID_LANGUAGES for lang in self.stats['language_distribution'].keys()):
            issues.append("No valid languages found")
        
        # Print safety verdict
        print(f"\n{'='*80}")
        if issues:
            print(f"⚠️  DATASET HAS ISSUES:")
            for i, issue in enumerate(issues, 1):
                print(f"   {i}. {issue}")
            print(f"{'='*80}\n")
            return False
        else:
            print(f"✅ DATASET IS SAFE FOR TRAINING")
            print(f"{'='*80}\n")
            return True

def main():
    """Validate all normalized datasets."""
    normalized_dir = Path("data/normalized")
    
    if not normalized_dir.exists():
        print(f"[ERROR] {normalized_dir} does not exist")
        return
    
    # Find all .jsonl files
    jsonl_files = sorted(normalized_dir.glob("*.jsonl"))
    
    if not jsonl_files:
        print(f"[ERROR] No .jsonl files found in {normalized_dir}")
        return
    
    print(f"\nFound {len(jsonl_files)} normalized dataset(s)")
    
    results = {}
    for fpath in jsonl_files:
        validator = NormalizedDatasetValidator(str(fpath))
        is_safe = validator.validate()
        results[fpath.name] = is_safe
    
    # Summary
    print(f"\n{'='*80}")
    print("VALIDATION SUMMARY")
    print(f"{'='*80}")
    for dataset_name, is_safe in results.items():
        status = "✅ SAFE" if is_safe else "❌ UNSAFE"
        print(f"  {dataset_name:25s} {status}")
    
    all_safe = all(results.values())
    print(f"\n{'='*80}")
    if all_safe:
        print("✅ ALL DATASETS ARE READY FOR TRAINING")
    else:
        print("❌ SOME DATASETS HAVE ISSUES - FIX BEFORE TRAINING")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    main()
