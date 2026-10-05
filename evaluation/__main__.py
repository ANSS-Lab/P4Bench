"""CLI entry point: python -m evaluation"""
import argparse
import json
import sys

from evaluation.engine import TestEngine


def main():
    parser = argparse.ArgumentParser(
        description='P4 benchmark evaluation engine'
    )
    parser.add_argument('--task', required=True, metavar='DIR',
                        help='Path to task directory containing task.yaml')
    parser.add_argument('--p4', required=True, metavar='FILE',
                        help='Generated P4 file to evaluate')
    parser.add_argument('--entries', metavar='FILE',
                        help='Generated entries JSON file')
    parser.add_argument('--output', metavar='FILE',
                        help='Write JSON result to file instead of stdout')
    args = parser.parse_args()

    engine = TestEngine()
    result = engine.run(
        task_dir=args.task,
        p4_file=args.p4,
        entries_file=args.entries,
    )

    out = json.dumps(result.to_dict(), indent=2)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(out)
        print(f'Results written to {args.output}')
    else:
        print(out)

    # Print summary
    print(f'\n=== {result.task_name} ===', file=sys.stderr)
    print(f'Compile gate:     {"PASS" if result.l1_compile else "FAIL"}', file=sys.stderr)
    if not result.l1_compile:
        print(f'  {result.l1_error}', file=sys.stderr)
        sys.exit(1)
    print(f'Functional score: {result.l3_score:.3f}  '
          f'(public={result.l3_public:.3f}, hidden={result.l3_hidden:.3f})', file=sys.stderr)
    for t in result.tests:
        mark = '✓' if t.result == 'PASS' else ('~' if t.result == 'SKIPPED' else '✗')
        vis = 'pub' if t.visibility == 'public' else 'hid'
        detail = f'  {t.detail}' if t.detail else ''
        print(f'  {mark} [{vis}] {t.name}{detail}', file=sys.stderr)

    if any(t.result == 'FAIL' for t in result.tests):
        sys.exit(1)


if __name__ == '__main__':
    main()
