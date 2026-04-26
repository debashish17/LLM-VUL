"""
Dependency Verification Script
Checks if all required packages are installed and compatible
"""

import sys

def check_package(package_name, import_name=None):
    """Check if a package is installed and importable"""
    if import_name is None:
        import_name = package_name
    
    try:
        module = __import__(import_name)
        version = getattr(module, '__version__', 'unknown')
        print(f"✓ {package_name:20s} {version}")
        return True
    except ImportError as e:
        print(f"✗ {package_name:20s} NOT INSTALLED - {e}")
        return False

def check_gpu():
    """Check if GPU is available for PyTorch"""
    try:
        import torch
        if torch.cuda.is_available():
            print(f"\n✓ GPU Available: {torch.cuda.get_device_name(0)}")
            print(f"  CUDA Version: {torch.version.cuda}")
            print(f"  Number of GPUs: {torch.cuda.device_count()}")
            return True
        else:
            print("\n⚠ GPU NOT available - will use CPU (slower)")
            return False
    except Exception as e:
        print(f"\n✗ Error checking GPU: {e}")
        return False

def main():
    print("=" * 60)
    print("DEPENDENCY VERIFICATION")
    print("=" * 60)
    
    print("\n[1] Core ML Libraries:")
    all_ok = True
    all_ok &= check_package("xgboost")
    all_ok &= check_package("lightgbm")
    all_ok &= check_package("catboost")
    all_ok &= check_package("scikit-learn", "sklearn")
    all_ok &= check_package("imbalanced-learn", "imblearn")
    
    print("\n[2] Deep Learning:")
    all_ok &= check_package("torch")
    all_ok &= check_package("transformers")
    
    print("\n[3] Data Processing:")
    all_ok &= check_package("pandas")
    all_ok &= check_package("numpy")
    all_ok &= check_package("joblib")
    
    print("\n[4] Visualization:")
    all_ok &= check_package("matplotlib")
    all_ok &= check_package("seaborn")
    
    print("\n[5] Utilities:")
    all_ok &= check_package("tqdm")
    
    # Check GPU
    print("\n[6] GPU Check:")
    gpu_available = check_gpu()
    
    # Test imports for our modules
    print("\n[7] Testing Custom Modules:")
    try:
        sys.path.insert(0, '.')
        from models.ensemble_boosting import config
        print("✓ config.py imported successfully")
        
        from models.ensemble_boosting import data_loader
        print("✓ data_loader.py imported successfully")
        
        from models.ensemble_boosting import embedding_generator
        print("✓ embedding_generator.py imported successfully")
        
        from models.ensemble_boosting import class_balancer
        print("✓ class_balancer.py imported successfully")
        
        from models.ensemble_boosting import train
        print("✓ train.py imported successfully")
        
        from models.ensemble_boosting import ensemble
        print("✓ ensemble.py imported successfully")
        
        from models.ensemble_boosting import evaluate
        print("✓ evaluate.py imported successfully")
        
    except Exception as e:
        print(f"✗ Error importing custom modules: {e}")
        all_ok = False
    
    # Final status
    print("\n" + "=" * 60)
    if all_ok:
        print("✅ ALL DEPENDENCIES VERIFIED - READY TO RUN")
        if gpu_available:
            print("🚀 GPU acceleration enabled for faster training")
        else:
            print("⚠️  Running on CPU - training will be slower")
    else:
        print("❌ SOME DEPENDENCIES MISSING - INSTALL REQUIRED PACKAGES")
    print("=" * 60)
    
    return 0 if all_ok else 1

if __name__ == '__main__':
    sys.exit(main())
