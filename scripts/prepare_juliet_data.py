"""
Prepare Juliet Test Suite data for training with CWE-based splitting.

This script:
1. Scans the Juliet Test Suite repository
2. Extracts labeled C/C++ files (_bad = vulnerable, _good = safe)
3. Splits by CWE category (no overlap between train/val/test)
4. Creates normalized JSONL files for training

Usage:
    python prepare_juliet_data.py <juliet_repo_path> [--train-size 5000] [--val-size 1000] [--test-size 2000]
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict
import random

# CWE categories for proper splitting
TRAIN_CWES = [
    'CWE78', 'CWE119', 'CWE121', 'CWE122', 'CWE124', 'CWE127',
    'CWE134', 'CWE176', 'CWE242', 'CWE252', 'CWE253', 'CWE259',
    'CWE338', 'CWE390', 'CWE391', 'CWE404', 'CWE457', 'CWE460',
    'CWE467', 'CWE468', 'CWE469', 'CWE478', 'CWE483', 'CWE484',
    'CWE526', 'CWE534', 'CWE535', 'CWE562', 'CWE563', 'CWE570',
    'CWE571', 'CWE606', 'CWE685', 'CWE688', 'CWE689', 'CWE690',
]

VAL_CWES = [
    'CWE23', 'CWE36', 'CWE191', 'CWE193', 'CWE195', 'CWE197',
    'CWE197', 'CWE321', 'CWE325', 'CWE327', 'CWE328', 'CWE329',
    'CWE369', 'CWE401', 'CWE415', 'CWE416', 'CWE426', 'CWE427',
    'CWE464', 'CWE475', 'CWE476', 'CWE480', 'CWE481', 'CWE482',
]

TEST_CWES = [
    'CWE126', 'CWE190', 'CWE194', 'CWE196', 'CWE244', 'CWE256',
    'CWE257', 'CWE258', 'CWE319', 'CWE364', 'CWE366', 'CWE367',
    'CWE377', 'CWE396', 'CWE397', 'CWE398', 'CWE399', 'CWE400',
    'CWE459', 'CWE462', 'CWE463', 'CWE479', 'CWE497', 'CWE605',
    'CWE680', 'CWE681', 'CWE690', 'CWE758', 'CWE761', 'CWE762',
]


def extract_cwe_from_path(filepath: str) -> str:
    """Extract CWE number from file path."""
    match = re.search(r'CWE(\d+)', filepath)
    return f"CWE{match.group(1)}" if match else None


def extract_ground_truth(filepath: str) -> str:
    """Extract ground truth label from filename."""
    filename = os.path.basename(filepath)
    
    # _bad suffix = vulnerable
    if '_bad.' in filename or '_bad_' in filename:
        return 'vulnerable'
    
    # _good suffix = safe (but goodG2B, goodB2G are actually vulnerable patterns)
    if '_good.' in filename or '_good_' in filename:
        # Check for good-to-bad flow variants (these are vulnerable)
        if 'goodG2B' in filename or 'goodB2G' in filename or 'good2' in filename:
            return 'vulnerable'
        return 'safe'
    
    return None


def find_juliet_files(repo_path: str) -> Dict[str, List[Tuple[str, str]]]:
    """
    Find all labeled Juliet files organized by CWE.
    
    Returns:
        dict: {cwe -> [(filepath, label), ...]}
    """
    files_by_cwe = defaultdict(list)
    
    testcases_dir = os.path.join(repo_path, 'testcases')
    if not os.path.exists(testcases_dir):
        raise ValueError(f"Testcases directory not found: {testcases_dir}")
    
    print(f"Scanning {testcases_dir}...")
    
    for root, dirs, files in os.walk(testcases_dir):
        for filename in files:
            # Only C/C++ files
            if not (filename.endswith('.c') or filename.endswith('.cpp')):
                continue
            
            filepath = os.path.join(root, filename)
            
            # Extract CWE and label
            cwe = extract_cwe_from_path(filepath)
            label = extract_ground_truth(filepath)
            
            if cwe and label:
                files_by_cwe[cwe].append((filepath, label))
    
    # Print statistics
    print(f"\nFound files for {len(files_by_cwe)} CWE categories:")
    for cwe in sorted(files_by_cwe.keys()):
        vuln_count = sum(1 for _, lbl in files_by_cwe[cwe] if lbl == 'vulnerable')
        safe_count = sum(1 for _, lbl in files_by_cwe[cwe] if lbl == 'safe')
        print(f"  {cwe}: {len(files_by_cwe[cwe])} files (vuln={vuln_count}, safe={safe_count})")
    
    return files_by_cwe


def read_code_file(filepath: str) -> str:
    """Read code file with error handling."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None


def create_splits(files_by_cwe: Dict[str, List], 
                  train_size: int, 
                  val_size: int, 
                  test_size: int) -> Tuple[List, List, List]:
    """
    Create train/val/test splits based on CWE categories.
    
    Returns:
        (train_samples, val_samples, test_samples)
    """
    train_samples = []
    val_samples = []
    test_samples = []
    
    # Sample from each CWE category
    for cwe, files in files_by_cwe.items():
        if cwe in TRAIN_CWES:
            target_list = train_samples
            target_size = train_size
        elif cwe in VAL_CWES:
            target_list = val_samples
            target_size = val_size
        elif cwe in TEST_CWES:
            target_list = test_samples
            target_size = test_size
        else:
            # Unknown CWE - skip
            continue
        
        # Shuffle files for this CWE
        random.shuffle(files)
        
        # Add files until we reach target size (distributed across CWEs)
        files_to_add = min(len(files), max(10, target_size // 20))  # At least 10 per CWE
        target_list.extend(files[:files_to_add])
    
    # Shuffle final splits
    random.shuffle(train_samples)
    random.shuffle(val_samples)
    random.shuffle(test_samples)
    
    # Trim to exact sizes
    train_samples = train_samples[:train_size]
    val_samples = val_samples[:val_size]
    test_samples = test_samples[:test_size]
    
    return train_samples, val_samples, test_samples


def normalize_juliet_samples(samples: List[Tuple[str, str]], split_name: str) -> List[Dict]:
    """
    Convert file samples to normalized format.
    
    Format matches existing normalized data:
    {
        "func": "code here",
        "target": 0 or 1,
        "project": "juliet",
        "commit_id": "CWE123",
        "file_path": "path/to/file.cpp"
    }
    """
    normalized = []
    
    for filepath, label in samples:
        code = read_code_file(filepath)
        if not code:
            continue
        
        # Skip very large files (>100KB)
        if len(code) > 100000:
            continue
        
        cwe = extract_cwe_from_path(filepath)
        
        sample = {
            'func': code,
            'target': 1 if label == 'vulnerable' else 0,
            'project': 'juliet',
            'commit_id': cwe,
            'file_path': os.path.relpath(filepath, start=os.path.dirname(filepath)),
        }
        normalized.append(sample)
    
    print(f"\n{split_name} split:")
    print(f"  Total samples: {len(normalized)}")
    vuln_count = sum(1 for s in normalized if s['target'] == 1)
    safe_count = len(normalized) - vuln_count
    print(f"  Vulnerable: {vuln_count} ({vuln_count/len(normalized)*100:.1f}%)")
    print(f"  Safe: {safe_count} ({safe_count/len(normalized)*100:.1f}%)")
    
    return normalized


def save_jsonl(samples: List[Dict], output_path: str):
    """Save samples in JSONL format."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for sample in samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"Saved {len(samples)} samples to {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Prepare Juliet Test Suite data')
    parser.add_argument('repo_path', help='Path to Juliet Test Suite repository')
    parser.add_argument('--train-size', type=int, default=5000, help='Training samples')
    parser.add_argument('--val-size', type=int, default=1000, help='Validation samples')
    parser.add_argument('--test-size', type=int, default=2000, help='Test samples')
    parser.add_argument('--output-dir', default='data/juliet', help='Output directory')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    
    args = parser.parse_args()
    
    # Set random seed
    random.seed(args.seed)
    
    print("=" * 70)
    print("JULIET TEST SUITE DATA PREPARATION")
    print("=" * 70)
    print(f"\nRepository: {args.repo_path}")
    print(f"Target sizes: train={args.train_size}, val={args.val_size}, test={args.test_size}")
    print(f"\nCWE Split Strategy:")
    print(f"  Training CWEs: {len(TRAIN_CWES)} categories")
    print(f"  Validation CWEs: {len(VAL_CWES)} categories")
    print(f"  Test CWEs: {len(TEST_CWES)} categories")
    print("\n" + "=" * 70)
    
    # Step 1: Find all files
    files_by_cwe = find_juliet_files(args.repo_path)
    
    if not files_by_cwe:
        print("\nERROR: No labeled files found!")
        return
    
    # Step 2: Create splits
    print("\n" + "=" * 70)
    print("CREATING SPLITS")
    print("=" * 70)
    
    train_samples, val_samples, test_samples = create_splits(
        files_by_cwe, args.train_size, args.val_size, args.test_size
    )
    
    print(f"\nRaw samples collected:")
    print(f"  Train: {len(train_samples)}")
    print(f"  Val: {len(val_samples)}")
    print(f"  Test: {len(test_samples)}")
    
    # Step 3: Normalize samples
    print("\n" + "=" * 70)
    print("NORMALIZING SAMPLES")
    print("=" * 70)
    
    train_normalized = normalize_juliet_samples(train_samples, "Train")
    val_normalized = normalize_juliet_samples(val_samples, "Validation")
    test_normalized = normalize_juliet_samples(test_samples, "Test")
    
    # Step 4: Save to JSONL
    print("\n" + "=" * 70)
    print("SAVING FILES")
    print("=" * 70 + "\n")
    
    save_jsonl(train_normalized, os.path.join(args.output_dir, 'juliet_train.jsonl'))
    save_jsonl(val_normalized, os.path.join(args.output_dir, 'juliet_val.jsonl'))
    save_jsonl(test_normalized, os.path.join(args.output_dir, 'juliet_test.jsonl'))
    
    print("\n" + "=" * 70)
    print("✅ JULIET DATA PREPARATION COMPLETE")
    print("=" * 70)
    print(f"\nOutput files:")
    print(f"  {os.path.join(args.output_dir, 'juliet_train.jsonl')}")
    print(f"  {os.path.join(args.output_dir, 'juliet_val.jsonl')}")
    print(f"  {os.path.join(args.output_dir, 'juliet_test.jsonl')}")
    print("\nNext steps:")
    print("  1. Review CWE splits (no overlap between train/val/test)")
    print("  2. Update data loader to include juliet_train.jsonl")
    print("  3. Run training with mixed dataset")
    print("  4. Validate on juliet_test.jsonl (unseen CWEs)")


if __name__ == '__main__':
    main()
