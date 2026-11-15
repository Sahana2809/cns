"""Unified Test Runner for SHADOW Wi-Fi.

Discovers and runs every tests/test_*.py module in the project, so this
stays correct as modules are added rather than needing a hand-maintained
list (the previous hardcoded list only covered Part 1 and part of Part 3,
silently skipping authentication/key-exchange/secure-session tests).

Can be executed directly with:
    python run_tests.py
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

TESTS_DIR = Path(__file__).resolve().parent / "tests"


def run_test_module(module_name: str) -> tuple[int, int]:
    """Execute all test_* functions in a module."""
    import importlib
    mod = importlib.import_module(module_name)
    test_funcs = [
        getattr(mod, name)
        for name in dir(mod)
        if name.startswith("test_") and callable(getattr(mod, name))
    ]
    setup_fn = getattr(mod, "setup_function", None)

    passed = 0
    failed = 0
    print(f"\n---> Running {module_name} ({len(test_funcs)} tests):")
    for fn in test_funcs:
        if setup_fn:
            setup_fn()
        try:
            fn()
            print(f"  [PASS] {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {fn.__name__}: {e}")
            failed += 1
    return passed, failed


def main():
    print("=" * 60)
    print("  SHADOW Wi-Fi — Test Suite Execution")
    print("=" * 60)

    modules = sorted(
        f"tests.{path.stem}"
        for path in TESTS_DIR.glob("test_*.py")
    )

    total_passed = 0
    total_failed = 0

    for m in modules:
        try:
            p, f = run_test_module(m)
            total_passed += p
            total_failed += f
        except Exception as e:
            print(f"[-] Could not load module {m}: {e}")
            total_failed += 1

    print("\n" + "=" * 60)
    print(f"  SUMMARY: {total_passed} Passed, {total_failed} Failed out of {total_passed + total_failed} Tests")
    print("=" * 60)

    if total_failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

