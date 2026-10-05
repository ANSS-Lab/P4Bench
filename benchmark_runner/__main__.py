"""CLI entry point: python -m benchmark_runner"""
import argparse
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from benchmark_runner.runner import BenchmarkRunner
from evaluation.engine import TestEngine


def _git_info() -> dict:
    out = {}
    try:
        out['commit'] = subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        pass
    try:
        out['branch'] = subprocess.check_output(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        pass
    return out


def _slug(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '-', s or '').strip('-') or 'run'


def _build_run_id(model: str, max_retries: int, tag: str, task_slug: str = '') -> str:
    date = datetime.now(timezone.utc).strftime('%Y%m%d')
    model_slug = _slug(model or 'llm')
    tag_slug = _slug(tag) if tag else 'untagged'
    parts = [date, model_slug, f'r{max_retries}', tag_slug]
    if task_slug:
        parts.append(_slug(task_slug))
    return '_'.join(parts)


def _parse_opt_value(raw: str):
    """Coerce --adapter-opts values: true/false -> bool, digits -> int, else str."""
    low = raw.lower()
    if low in ('true', 'false'):
        return low == 'true'
    if raw.lstrip('-').isdigit():
        return int(raw)
    return raw


def _parse_adapter_opts(pairs):
    """Parse a list of 'key=value' strings into a kwargs dict."""
    opts = {}
    for pair in pairs or []:
        if '=' not in pair:
            raise ValueError(f"--adapter-opts expects key=value, got: {pair!r}")
        key, _, val = pair.partition('=')
        opts[key.strip()] = _parse_opt_value(val.strip())
    return opts


def _load_adapter(adapter_path: str, model: str = None, opts: dict = None):
    """Dynamically load an adapter from a Python file."""
    spec = importlib.util.spec_from_file_location('adapter_module', adapter_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Find a class that inherits from LLMAdapter
    from adapters.base import LLMAdapter
    for name in dir(mod):
        obj = getattr(mod, name)
        if (isinstance(obj, type) and issubclass(obj, LLMAdapter)
                and obj is not LLMAdapter):
            kwargs = dict(opts or {})
            if model:
                kwargs['model'] = model
            try:
                return obj(**kwargs)
            except TypeError:
                if opts:
                    raise  # caller-supplied opts must be honored
                return obj()

    raise ValueError(f'No LLMAdapter subclass found in {adapter_path}')


def main():
    parser = argparse.ArgumentParser(
        description='P4 benchmark runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run the whole corpus with an LLM adapter
  python -m benchmark_runner --adapter adapters/gpt_adapter.py --model <model> \\
      --tasks benchmark/ --output results/<model>.json

  # Run a single task
  python -m benchmark_runner --adapter adapters/gpt_adapter.py --model <model> \\
      --task benchmark/redesign/ipv4_routing_anchor
""",
    )

    # Task selection
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--tasks', metavar='DIR',
                       help='Directory containing benchmark tasks (recurses for task.yaml)')
    group.add_argument('--task', metavar='DIR',
                       help='Single task directory')

    # Adapter
    parser.add_argument('--adapter', metavar='FILE', required=True,
                        help='Python file with LLMAdapter subclass')
    parser.add_argument('--model', metavar='NAME',
                        help='Model name to pass to the adapter')
    parser.add_argument('--adapter-opts', nargs='*', metavar='KEY=VAL', default=[],
                        help='Extra kwargs forwarded to the adapter constructor '
                             '(e.g. --adapter-opts agent_mode=true timeout=900)')

    # Retry
    parser.add_argument('--max-retries', type=int, default=0, metavar='N',
                        help='Max feedback-guided retries per task on failure (default: 0)')

    # Parallelism
    parser.add_argument('--workers', type=int, default=1, metavar='N',
                        help='Evaluate up to N tasks concurrently (default: 1). '
                             'Each task gets an isolated switch (free Thrift port + '
                             'unique device-id), so concurrent runs do not collide.')

    # Run metadata
    parser.add_argument('--run-id', metavar='ID',
                        help='Run identifier; default: <UTCdate>_<model>_r<retries>_<tag>')
    parser.add_argument('--tag', metavar='TEXT', default='',
                        help='Freeform cohort label (e.g. "baseline", "draw1")')
    parser.add_argument('--note', metavar='TEXT', default='',
                        help='Freeform notes recorded in meta.notes')

    # Generation-only mode
    parser.add_argument('--generate-only', action='store_true',
                        help='Call the LLM and save generated files but skip BMv2 evaluation. '
                             'Use --save-generated (or the default results/runs/<run-id>/generated/) '
                             'to control where files land. Replay later with file_adapter.')

    # Output
    parser.add_argument('--output', metavar='FILE',
                        help='Write JSON report to file (default: results/runs/<run-id>/report.json)')
    parser.add_argument('--save-generated', metavar='DIR',
                        help='Save generated .p4 and entries.json files to this directory '
                             '(default: results/runs/<run-id>/generated)')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress progress output')

    args = parser.parse_args()

    # Build adapter
    opts = _parse_adapter_opts(args.adapter_opts)
    adapter = _load_adapter(args.adapter, args.model, opts=opts)

    tasks_root = args.tasks or args.task

    # Build run-id + default output/save paths.
    # For single-task runs, append the task name so back-to-back runs
    # with the same (model, retries, tag) don't clobber each other.
    task_slug = Path(args.task).name if args.task else ''
    run_id = args.run_id or _build_run_id(
        args.model, args.max_retries, args.tag, task_slug
    )
    run_dir = Path('results/runs') / run_id
    output_file = args.output or str(run_dir / 'report.json')
    save_generated_dir = args.save_generated or str(run_dir / 'generated')

    # Effective decoding settings, read from the adapter (never api keys)
    adapter_kwargs = {
        key: getattr(adapter, key)
        for key in ('model', 'temperature', 'max_tokens')
        if getattr(adapter, key, None) is not None
    }

    meta = {
        'run_id': run_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'model': args.model,
        'adapter': args.adapter,
        'adapter_kwargs': adapter_kwargs,
        'max_retries': args.max_retries,
        'workers': args.workers,
        'tag': args.tag,
        'tasks_input': {
            'mode': 'single' if args.task else 'root',
            'path': tasks_root,
        },
        'git': _git_info(),
        'command': ' '.join(sys.argv),
        'notes': args.note,
    }

    runner = BenchmarkRunner(adapter=adapter, engine=TestEngine())
    report = runner.run_tasks(
        tasks_root=tasks_root,
        output_file=output_file,
        verbose=not args.quiet,
        max_retries=args.max_retries,
        save_generated_dir=save_generated_dir,
        meta=meta,
        workers=args.workers,
        generate_only=args.generate_only,
    )

    # Print summary
    print(f'\n=== Benchmark Summary ===')
    print(f'Tasks:          {report["total_tasks"]}')
    print(f'Compile rate:   {report.get("l1_pass_rate", 0):.1%}')
    print(f'Mean F:         {report.get("l3_mean", 0):.3f}  (functional score over compiled tasks)')
    print(f'Gen gap:        {report.get("generalization_gap", 0):.3f}  (public minus hidden pass rate)')

    print(f'\nFull report: {output_file}')

    # Exit with failure if any task scored 0
    all_pass = all(
        t.get('l3_score', 0) >= 1.0
        for t in report.get('tasks', [])
        if t.get('l1_compile')
    )
    sys.exit(0 if all_pass else 1)


if __name__ == '__main__':
    main()
