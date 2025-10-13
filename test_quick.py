"""
Quick Test Script - Verify Core Components
Run this BEFORE creating notebooks to ensure everything works

Usage: python test_quick.py
"""
import sys
import os
from pathlib import Path

# Add src to path
sys.path.append('.')

print("="*70)
print("VULNERABILITY DETECTOR - QUICK TEST SUITE")
print("="*70)
print()

# Track test results
tests_passed = 0
tests_failed = 0
test_details = []

def test_section(name):
    """Print test section header"""
    print(f"\n{'='*70}")
    print(f"TEST: {name}")
    print(f"{'='*70}")

def test_result(passed, message):
    """Track and print test result"""
    global tests_passed, tests_failed
    if passed:
        tests_passed += 1
        print(f"✅ {message}")
    else:
        tests_failed += 1
        print(f"❌ {message}")
    test_details.append((passed, message))

# =============================================================================
# TEST 1: PROJECT STRUCTURE
# =============================================================================
test_section("Project Structure")

required_dirs = [
    'src',
    'src/parser',
    'src/detector', 
    'src/utils',
    'src/api',
    'data',
    'models',
    'scripts',
    'tests'
]

for dir_path in required_dirs:
    exists = Path(dir_path).exists()
    test_result(exists, f"Directory exists: {dir_path}")
    if not exists:
        print(f"   → Create with: mkdir -p {dir_path}")

# Check for __init__.py files
init_files = [
    'src/__init__.py',
    'src/parser/__init__.py',
    'src/detector/__init__.py',
    'src/utils/__init__.py',
    'src/api/__init__.py'
]

for init_file in init_files:
    exists = Path(init_file).exists()
    test_result(exists, f"Init file exists: {init_file}")
    if not exists:
        print(f"   → Create with: touch {init_file}")

# =============================================================================
# TEST 2: DEPENDENCIES
# =============================================================================
test_section("Python Dependencies")

dependencies = {
    'torch': 'PyTorch',
    'transformers': 'HuggingFace Transformers',
    'tree_sitter_language_pack': 'Tree-sitter',
    'fastapi': 'FastAPI',
    'pandas': 'Pandas',
    'numpy': 'NumPy',
    'sklearn': 'Scikit-learn'
}

for module, name in dependencies.items():
    try:
        __import__(module)
        test_result(True, f"{name} installed")
    except ImportError:
        test_result(False, f"{name} NOT installed")
        print(f"   → Install with: pip install {module.replace('_', '-')}")

# =============================================================================
# TEST 3: CODE PARSER
# =============================================================================
test_section("Code Parser Module")

try:
    from src.parser.code_parser import CodeParser
    test_result(True, "CodeParser imported successfully")
    
    # Initialize parser
    parser = CodeParser()
    test_result(True, "CodeParser initialized")
    
    # Test supported languages
    supported = parser.get_supported_languages()
    test_result(len(supported) >= 4, f"Supports {len(supported)} languages (need ≥4)")
    print(f"   Supported: {', '.join(sorted(supported)[:5])}...")
    
    # Test language detection
    test_cases = [
        ('test.py', 'python'),
        ('test.java', 'java'),
        ('test.cpp', 'cpp'),
        ('test.js', 'javascript')
    ]
    
    for filename, expected_lang in test_cases:
        detected = parser.detect_language(filename)
        test_result(detected == expected_lang, 
                   f"Language detection: {filename} → {detected}")
    
    # Test code parsing
    test_code = """
def unsafe_query(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return execute(query)

def safe_query(user_input):
    query = "SELECT * FROM users WHERE name = ?"
    return execute(query, (user_input,))
"""
    
    parse_result = parser.parse_code(test_code, 'python')
    test_result(parse_result.get('success'), "Parse Python code")
    
    # Test function extraction
    functions = parser.extract_functions(parse_result)
    test_result(len(functions) == 2, f"Extract functions (found {len(functions)})")
    
    if len(functions) >= 2:
        func_names = [f['name'] for f in functions]
        test_result('unsafe_query' in func_names, "Found 'unsafe_query' function")
        test_result('safe_query' in func_names, "Found 'safe_query' function")
    
    # Test code metrics
    metrics = parser.get_code_metrics(test_code, 'python')
    test_result('total_lines' in metrics, "Calculate code metrics")
    test_result(metrics['total_lines'] > 0, f"Line count: {metrics['total_lines']}")

except Exception as e:
    test_result(False, f"Code Parser failed: {e}")
    print(f"\n   ERROR DETAILS: {e}")
    print(f"   → Make sure src/parser/code_parser.py exists")

# =============================================================================
# TEST 4: CWE MAPPING
# =============================================================================
test_section("CWE Detection Module")

try:
    from src.utils.cwe_mapping import CWEDatabase, detect_cwe
    test_result(True, "CWE module imported successfully")
    
    # Test CWE database
    all_cwes = CWEDatabase.get_all_cwes()
    test_result(len(all_cwes) >= 5, f"CWE database loaded ({len(all_cwes)} CWEs)")
    
    # Test pattern detection
    vulnerable_code = """
def login(username, password):
    query = "SELECT * FROM users WHERE user='" + username + "' AND pass='secret123'"
    cursor.execute(query)
"""
    
    cwe_results = detect_cwe(vulnerable_code)
    test_result(len(cwe_results) > 0, f"Detect CWE patterns (found {len(cwe_results)})")
    
    if cwe_results:
        print(f"   Detected vulnerabilities:")
        for cwe in cwe_results:
            print(f"     - {cwe['cwe_id']}: {cwe['name']} ({cwe['severity']})")
    
    # Test specific CWE info
    sql_injection = CWEDatabase.get_cwe_info('CWE-89')
    test_result(sql_injection is not None, "Get CWE-89 info (SQL Injection)")

except Exception as e:
    test_result(False, f"CWE Detection failed: {e}")
    print(f"\n   ERROR DETAILS: {e}")
    print(f"   → Make sure src/utils/cwe_mapping.py exists")

# =============================================================================
# TEST 5: MODEL COMPONENTS
# =============================================================================
test_section("ML Model Components")

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
    
    test_result(True, "Transformers library works")
    
    # Check CUDA availability
    cuda_available = torch.cuda.is_available()
    device_name = torch.cuda.get_device_name(0) if cuda_available else "CPU"
    test_result(True, f"Device: {device_name}")
    
    # Test model loading (pretrained, not fine-tuned)
    print("\n   Loading pretrained CodeBERT (this may take a minute)...")
    model_name = 'microsoft/codebert-base'
    
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    test_result(True, "Tokenizer loaded")
    
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        num_labels=2
    )
    test_result(True, "Model loaded")
    
    # Test tokenization
    test_code = "def test(): pass"
    inputs = tokenizer(test_code, return_tensors="pt", truncation=True, max_length=512)
    test_result('input_ids' in inputs, "Tokenization works")
    
    # Test inference
    model.eval()
    with torch.no_grad():
        outputs = model(**inputs)
        prediction = torch.argmax(outputs.logits, dim=-1).item()
    
    test_result(prediction in [0, 1], f"Model inference works (pred={prediction})")
    print(f"   ⚠️  Note: This is an untrained model, prediction is random!")

except Exception as e:
    test_result(False, f"Model components failed: {e}")
    print(f"\n   ERROR DETAILS: {e}")

# =============================================================================
# TEST 6: DATA AVAILABILITY
# =============================================================================
test_section("Dataset Availability")

datasets_to_check = [
    ('data/devign', 'Devign dataset', 
     'git clone https://github.com/epicosy/devign.git data/devign'),
    ('data/devign/data.json', 'Devign data file', None)
]

for path, name, install_cmd in datasets_to_check:
    exists = Path(path).exists()
    test_result(exists, f"{name}: {'Found' if exists else 'Not found'}")
    if not exists and install_cmd:
        print(f"   → Download with: {install_cmd}")

# Try to load Devign if available
if Path('data/devign/data.json').exists():
    try:
        import json
        with open('data/devign/data.json', 'r') as f:
            data = json.load(f)
        test_result(True, f"Load Devign data ({len(data)} samples)")
    except Exception as e:
        test_result(False, f"Load Devign data failed: {e}")

# =============================================================================
# TEST 7: OPTIONAL COMPONENTS
# =============================================================================
test_section("Optional Components (Can be created later)")

optional_files = [
    ('src/detector/model.py', 'VulnerabilityDetector class'),
    ('src/api/main.py', 'FastAPI server'),
    ('src/api/schemas.py', 'API schemas'),
    ('scripts/scan_file.py', 'File scanner CLI'),
    ('scripts/scan_directory.py', 'Directory scanner CLI'),
    ('notebooks/02_data_preparation.ipynb', 'Data prep notebook'),
    ('notebooks/03_model_training.ipynb', 'Training notebook'),
]

print("\nOptional files (create when needed):")
for filepath, description in optional_files:
    exists = Path(filepath).exists()
    status = "✅" if exists else "⏸️ "
    print(f"  {status} {filepath} - {description}")

# =============================================================================
# FINAL SUMMARY
# =============================================================================
print("\n" + "="*70)
print("TEST SUMMARY")
print("="*70)
print(f"Tests Passed: {tests_passed}")
print(f"Tests Failed: {tests_failed}")
print(f"Total Tests:  {tests_passed + tests_failed}")

if tests_failed == 0:
    print("\n🎉 ALL TESTS PASSED! You're ready to proceed!")
    print("\n📋 Next Steps:")
    print("   1. If dataset not downloaded:")
    print("      cd data && git clone https://github.com/epicosy/devign.git")
    print("   2. Create detector module: src/detector/model.py")
    print("   3. Create data preparation notebook")
    print("   4. Train your model!")
else:
    print(f"\n⚠️  {tests_failed} test(s) failed. Fix issues above before proceeding.")
    print("\nFailed tests:")
    for passed, message in test_details:
        if not passed:
            print(f"   ❌ {message}")

print("\n" + "="*70)

# Exit with appropriate code
sys.exit(0 if tests_failed == 0 else 1)