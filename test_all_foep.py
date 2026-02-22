#!/usr/bin/env python3
"""
Comprehensive FOEP Test Suite
Tests every single module and file in the FOEP project
"""

import os
import sys
import importlib
import traceback
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Test results tracking
passed = 0
failed = 0
errors = []

def test_import(module_path, import_name):
    """Test importing a module"""
    global passed, failed
    try:
        importlib.import_module(import_name)
        print(f"✅ PASS: {module_path}")
        passed += 1
        return True
    except Exception as e:
        error_msg = f"❌ FAIL: {module_path} - {str(e)}"
        print(error_msg)
        errors.append(error_msg)
        failed += 1
        return False

def test_file_exists(file_path):
    """Test if a file exists"""
    global passed, failed
    if os.path.exists(file_path):
        print(f"✅ PASS: File exists - {file_path}")
        passed += 1
        return True
    else:
        error_msg = f"❌ FAIL: File missing - {file_path}"
        print(error_msg)
        errors.append(error_msg)
        failed += 1
        return False

def main():
    global passed, failed
    
    print("=" * 60)
    print("🔍 COMPREHENSIVE FOEP TEST SUITE")
    print("=" * 60)
    
    project_root = Path(__file__).parent
    
    # Test 1: Core project files
    print("\n📋 Testing core project files...")
    core_files = [
        "setup.py",
        "requirements.txt",
        "requirements-dev.txt",
        "README.md",
        "config/config.yaml"
    ]
    
    for file in core_files:
        test_file_exists(project_root / file)
    
    # Test 2: Script files
    print("\nscriptId Testing CLI scripts...")
    script_files = [
        "scripts/foep_ingest.py",
        "scripts/foep_correlate.py", 
        "scripts/foep_report.py",
        "scripts/__init__.py"
    ]
    
    for file in script_files:
        test_file_exists(project_root / file)
    
    # Test 3: Core package structure
    print("\n📦 Testing core package structure...")
    core_packages = [
        "src/foep/__init__.py",
        "src/foep/core/__init__.py",
        "src/foep/core/config.py",
        "src/foep/core/pipeline.py"
    ]
    
    for file in core_packages:
        test_file_exists(project_root / file)
    
    # Test 4: Ingest package
    print("\n📥 Testing ingest package...")
    ingest_files = [
        "src/foep/ingest/__init__.py",
        "src/foep/ingest/forensic/__init__.py",
        "src/foep/ingest/forensic/disk.py",
        "src/foep/ingest/forensic/memory.py", 
        "src/foep/ingest/forensic/logs.py",
        "src/foep/ingest/osint/__init__.py",
        "src/foep/ingest/osint/social.py",
        "src/foep/ingest/osint/breaches.py",
        "src/foep/ingest/osint/code_repos.py"
    ]
    
    for file in ingest_files:
        test_file_exists(project_root / file)
    
    # Test 5: Normalize package
    print("\n🔄 Testing normalize package...")
    normalize_files = [
        "src/foep/normalize/__init__.py",
        "src/foep/normalize/schema.py",
        "src/foep/normalize/hash_utils.py",
        "src/foep/normalize/transformer.py"
    ]
    
    for file in normalize_files:
        test_file_exists(project_root / file)
    
    # Test 6: Correlate package
    print("\n🔗 Testing correlate package...")
    correlate_files = [
        "src/foep/correlate/__init__.py",
        "src/foep/correlate/extractor.py",
        "src/foep/correlate/linker.py",
        "src/foep/correlate/graph_db.py"
    ]
    
    for file in correlate_files:
        test_file_exists(project_root / file)
    
    # Test 7: Credibility package
    print("\n📊 Testing credibility package...")
    credibility_files = [
        "src/foep/credibility/__init__.py",
        "src/foep/credibility/sources.py",
        "src/foep/credibility/scorer.py"
    ]
    
    for file in credibility_files:
        test_file_exists(project_root / file)
    
    # Test 8: Report package
    print("\n📄 Testing report package...")
    report_files = [
        "src/foep/report/__init__.py",
        "src/foep/report/redactor.py",
        "src/foep/report/custody.py",
        "src/foep/report/generator.py"
    ]
    
    for file in report_files:
        test_file_exists(project_root / file)
    
    # Test 9: Module imports (the real test)
    print("\n⚡ Testing module imports...")
    
    # Core modules
    test_import("foep.core.config", "foep.core.config")
    test_import("foep.core.pipeline", "foep.core.pipeline")
    
    # Ingest modules
    test_import("foep.ingest.forensic.disk", "foep.ingest.forensic.disk")
    test_import("foep.ingest.forensic.memory", "foep.ingest.forensic.memory")
    test_import("foep.ingest.forensic.logs", "foep.ingest.forensic.logs")
    test_import("foep.ingest.osint.social", "foep.ingest.osint.social")
    test_import("foep.ingest.osint.breaches", "foep.ingest.osint.breaches")
    test_import("foep.ingest.osint.code_repos", "foep.ingest.osint.code_repos")
    
    # Normalize modules
    test_import("foep.normalize.schema", "foep.normalize.schema")
    test_import("foep.normalize.hash_utils", "foep.normalize.hash_utils")
    test_import("foep.normalize.transformer", "foep.normalize.transformer")
    
    # Correlate modules
    test_import("foep.correlate.extractor", "foep.correlate.extractor")
    test_import("foep.correlate.linker", "foep.correlate.linker")
    test_import("foep.correlate.graph_db", "foep.correlate.graph_db")
    
    # Credibility modules
    test_import("foep.credibility.sources", "foep.credibility.sources")
    test_import("foep.credibility.scorer", "foep.credibility.scorer")
    
    # Report modules
    test_import("foep.report.redactor", "foep.report.redactor")
    test_import("foep.report.custody", "foep.report.custody")
    test_import("foep.report.generator", "foep.report.generator")
    
    # CLI scripts
    test_import("scripts.foep_ingest", "scripts.foep_ingest")
    test_import("scripts.foep_correlate", "scripts.foep_correlate")
    test_import("scripts.foep_report", "scripts.foep_report")
    
    # Test 10: End-to-end functionality
  
    print("\n🎯 Testing end-to-end functionality...")

    try:
    # Test 1: Create test evidence
        from foep.normalize.schema import Evidence, EntityType, ObservationType
        test_ev = Evidence(
            evidence_id="test::1",
            entity_type=EntityType.EMAIL,
            entity_value="test@example.com",
            observation_type=ObservationType.LOG_ARTIFACT,
            source="test",
            credibility_score=100
        )
    
    # Test 2: Load actual config from file (this is what was missing!)
        from foep.core.config import load_config
        config = load_config()  # This loads your actual config.yaml
    
    # Test 3: Create pipeline with real config
        from foep.core.pipeline import FOEPPipeline
        pipeline = FOEPPipeline(
            config=config,
            case_id="TEST",
            investigator="Test User"
        )
    
        print("✅ PASS: End-to-end objects created successfully")
        passed += 1
    
    except Exception as e:
        error_msg = f"❌ FAIL: End-to-end test failed - {str(e)}"
        print(error_msg)
        errors.append(error_msg)
        failed += 1
    
    # Final summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"✅ PASSED: {passed}")
    print(f"❌ FAILED: {failed}")
    print(f"🎯 TOTAL:  {passed + failed}")
    
    if failed > 0:
        print("\n🚨 ERRORS DETECTED:")
        for error in errors:
            print(f"  {error}")
        print(f"\n🔧 Fix the {failed} failed tests above")
        sys.exit(1)
    else:
        print("\n🎉 ALL TESTS PASSED! FOEP is ready to use!")
        sys.exit(0)

if __name__ == "__main__":
    main()
