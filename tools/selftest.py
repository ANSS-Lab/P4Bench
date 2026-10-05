#!/usr/bin/env python3
"""Dataset + harness integrity check — needs NO LLM and NO BMv2.

Loads every shipped task.yaml and builds every test-case packet (exercising any
custom_headers.py). Reports parse/build failures. Exit code 0 == all clean.

Run from the repository root:  python3 tools/selftest.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evaluation.config_loader import TaskConfig          # noqa: E402
from evaluation.packet_builder import build_packet       # noqa: E402

# Corpus size reported in the paper.
EXPECTED_TASKS, EXPECTED_TESTS = 130, 1914

def main() -> int:
    tasks = sorted((ROOT / "benchmark").rglob("task.yaml"))
    if not tasks:
        print("no task.yaml found under benchmark/", file=sys.stderr)
        return 1
    n_tasks = n_pkts = n_fail = 0
    for ty in tasks:
        td = ty.parent
        try:
            cfg = TaskConfig(str(td))
        except Exception as e:                            # noqa: BLE001
            print(f"FAIL  parse  {td.relative_to(ROOT)}: {e}")
            n_fail += 1
            continue
        n_tasks += 1
        for tc in cfg.test_cases:
            if "input" not in tc:
                continue
            n_pkts += 1
            try:
                build_packet(tc["input"], task_dir=str(td))
            except Exception as e:                        # noqa: BLE001
                print(f"FAIL  packet {td.relative_to(ROOT)} :: "
                      f"{tc.get('name', '?')}: {e}")
                n_fail += 1
    print(f"\n{n_tasks} tasks parsed, {n_pkts} packets built, {n_fail} failures")
    if (n_tasks, n_pkts) != (EXPECTED_TASKS, EXPECTED_TESTS):
        print(f"WARN  expected {EXPECTED_TASKS} tasks / {EXPECTED_TESTS} tests")
        return 1
    return 1 if n_fail else 0

if __name__ == "__main__":
    raise SystemExit(main())
