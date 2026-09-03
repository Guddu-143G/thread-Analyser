#!/usr/bin/env python3
"""
Unified Test Runner for Threat Analyser Backend.

Executes all unit test modules in `backend/tests/unit/` and reports test summary.
For live E2E tests in `backend/tests/e2e/`, ensure the FastAPI server is running on localhost:8000.
"""
import os
import sys
import unittest
import importlib.util
from pathlib import Path

# Safe terminal encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure backend root is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def run_unit_tests():
    print("=" * 70)
    print("THREAT ANALYSER - EXECUTING UNIT TEST SUITE")
    print("=" * 70)

    unit_dir = Path(__file__).resolve().parent / "unit"
    test_files = sorted(unit_dir.glob("test_*.py"))

    passed = 0
    skipped = 0
    failed = 0
    errors = []

    for test_file in test_files:
        module_name = test_file.stem
        print(f"\n[*] Running {module_name} ({test_file.name})...")
        try:
            # Check if file has unittest TestCase or standalone functions
            spec = importlib.util.spec_from_file_location(module_name, str(test_file))
            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)

            # Check if it has test functions
            test_funcs = [attr for attr in dir(mod) if attr.startswith("test_") and callable(getattr(mod, attr))]
            for attr in dir(mod):
                val = getattr(mod, attr)
                if isinstance(val, type) and issubclass(val, unittest.TestCase):
                    suite = unittest.defaultTestLoader.loadTestsFromTestCase(val)
                    runner = unittest.TextTestRunner(verbosity=1)
                    res = runner.run(suite)
                    if not res.wasSuccessful():
                        raise Exception(f"Unittest failure in {attr}")

            for func_name in test_funcs:
                func = getattr(mod, func_name)
                func()
                print(f"    [+] {func_name} passed")

            print(f"  [OK] {module_name} PASSED")
            passed += 1
        except ModuleNotFoundError as mne:
            print(f"  [SKIP] {module_name} SKIPPED (Missing dependency: {mne.name} - run 'pip install -r backend/requirements.txt')")
            skipped += 1
        except Exception as e:
            print(f"  [FAIL] {module_name} FAILED: {e}")
            failed += 1
            errors.append((module_name, str(e)))

    print("\n" + "=" * 70)
    print(f"UNIT TEST SUMMARY: {passed} Passed | {skipped} Skipped (uninstalled deps) | {failed} Failed")
    print("=" * 70)

    if errors:
        for mod_name, err in errors:
            print(f"  - {mod_name}: {err}")
        return False
    return True


if __name__ == "__main__":
    success = run_unit_tests()
    sys.exit(0 if success else 1)
