#!/usr/bin/env python3
"""
Complete FOEP Test Suite Runner
Executes all unit and integration tests with detailed reporting
"""

import os
import sys
import subprocess
import json
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

def run_command(cmd, cwd=None):
    """Run shell command and return result"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            cwd=cwd
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def test_unit_tests():
    """Run all unit tests"""
    print("🧪 Running Unit Tests...")
    print("-" * 50)
    
    unit_test_files = [
        "tests/unit/test_ingest.py",
        "tests/unit/test_normalize.py", 
        "tests/unit/test_redactor.py"
    ]
    
    passed = 0
    failed = 0
    
    for test_file in unit_test_files:
        if os.path.exists(test_file):
            print(f"Running {test_file}...")
            success, stdout, stderr = run_command(f"python -m pytest {test_file} -v")
            if success:
                print(f"✅ PASS: {test_file}")
                passed += 1
            else:
                print(f"❌ FAIL: {test_file}")
                print(f"Error: {stderr}")
                failed += 1
        else:
            print(f"⚠️  SKIP: {test_file} (not found)")
    
    return passed, failed

def test_integration_tests():
    """Run all integration tests"""
    print("\n🔗 Running Integration Tests...")
    print("-" * 50)
    
    integration_test_files = [
        "tests/integration/test_full_pipeline.py"
    ]
    
    passed = 0
    failed = 0
    
    for test_file in integration_test_files:
        if os.path.exists(test_file):
            print(f"Running {test_file}...")
            # Integration tests may need Neo4j running
            success, stdout, stderr = run_command(f"python -m pytest {test_file} -v")
            if success:
                print(f"✅ PASS: {test_file}")
                passed += 1
            else:
                print(f"❌ FAIL: {test_file}")
                print(f"Error: {stderr}")
                failed += 1
        else:
            print(f"⚠️  SKIP: {test_file} (not found)")
    
    return passed, failed

def test_individual_test_modules():
    """Test each test file can be imported and run individually"""
    print("\n🔍 Testing Individual Test Modules...")
    print("-" * 50)
    
    test_modules = [
        ("tests/unit/test_ingest.py", "test_ingest"),
        ("tests/unit/test_normalize.py", "test_normalize"), 
        ("tests/unit/test_redactor.py", "test_redactor"),
        ("tests/integration/test_full_pipeline.py", "test_full_pipeline")
    ]
    
    passed = 0
    failed = 0
    
    for test_file, module_name in test_modules:
        if os.path.exists(test_file):
            print(f"Testing {test_file} import...")
            try:
                # Import the test module
                spec = __import__(module_name, fromlist=[''])
                if hasattr(spec, 'main'):
                    # Run main if it exists
                    spec.main()
                print(f"✅ PASS: {test_file} import")
                passed += 1
            except Exception as e:
                print(f"❌ FAIL: {test_file} import - {e}")
                failed += 1
        else:
            print(f"⚠️  SKIP: {test_file} (not found)")
    
    return passed, failed

def test_test_file_structure():
    """Verify all expected test files exist"""
    print("\n📋 Verifying Test File Structure...")
    print("-" * 50)
    
    expected_files = [
        "tests/__init__.py",
        "tests/unit/__init__.py",
        "tests/unit/test_ingest.py",
        "tests/unit/test_normalize.py",
        "tests/unit/test_redactor.py",
        "tests/integration/__init__.py", 
        "tests/integration/test_full_pipeline.py"
    ]
    
    passed = 0
    failed = 0
    
    for file_path in expected_files:
        if os.path.exists(file_path):
            print(f"✅ PASS: {file_path}")
            passed += 1
        else:
            print(f"❌ FAIL: {file_path} (missing)")
            failed += 1
    
    return passed, failed

def main():
    print("=" * 60)
    print("🚀 COMPLETE FOEP TEST SUITE EXECUTION")
    print("=" * 60)
    
    total_passed = 0
    total_failed = 0
    
    # Test 1: File structure
    p, f = test_test_file_structure()
    total_passed += p
    total_failed += f
    
    # Test 2: Individual module imports
    p, f = test_individual_test_modules()
    total_passed += p
    total_failed += f
    
    # Test 3: Unit tests
    p, f = test_unit_tests()
    total_passed += p
    total_failed += f
    
    # Test 4: Integration tests
    p, f = test_integration_tests()
    total_passed += p
    total_failed += f
    
    # Final summary
    print("\n" + "=" * 60)
    print("📊 COMPLETE TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"✅ TOTAL PASSED: {total_passed}")
    print(f"❌ TOTAL FAILED: {total_failed}")
    print(f"🎯 OVERALL: {'SUCCESS' if total_failed == 0 else 'FAILURE'}")
    
    if total_failed > 0:
        print(f"\n🔧 {total_failed} test(s) failed - check output above for details")
        sys.exit(1)
    else:
        print("\n🎉 ALL TESTS PASSED! FOEP is fully functional!")
        sys.exit(0)

if __name__ == "__main__":
    main()

