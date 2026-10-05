"""
Benchmark runner: orchestrate LLM evaluation across tasks.

Workflow per task:
  1. Load task.yaml
  2. Build prompt
  3. Call adapter.generate()
  4. Write the generated P4 program and entries to disk
  5. Run evaluation (compile gate, then packet-level functional tests)
  6. Record results
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from evaluation.config_loader import TaskConfig
from evaluation.engine import TestEngine, EvalResult
from benchmark_runner.prompt_builder import build_prompt
from adapters.base import LLMAdapter


def _discover_tasks(tasks_root: str) -> list[Path]:
    """Find all task directories (containing task.yaml) under tasks_root."""
    import os as _os
    root = Path(tasks_root)
    if (root / 'task.yaml').exists():
        return [root]
    found = []
    for dirpath, _dirs, filenames in _os.walk(tasks_root, followlinks=True):
        if 'task.yaml' in filenames:
            found.append(Path(dirpath))
    return sorted(found)


def _assemble_full_program(generated: dict, task_dir: Path, tmp_dir: str):
    """Write generated P4 and entries to temp files. Returns (p4_path, entries_path)."""
    p4_code = generated.get('p4_code', '')
    entries = generated.get('entries')

    p4_path = os.path.join(tmp_dir, 'generated.p4')
    with open(p4_path, 'w') as f:
        f.write(p4_code)

    entries_path = None
    if entries:
        entries_path = os.path.join(tmp_dir, 'generated_entries.json')
        with open(entries_path, 'w') as f:
            json.dump(entries, f, indent=2)

    return p4_path, entries_path


def _build_feedback(result: EvalResult) -> str:
    """Build a feedback string from a failed evaluation result."""
    lines = []
    if not result.l1_compile:
        lines.append("Compilation failed with this error:")
        lines.append("```")
        lines.append(result.l1_error.strip())
        lines.append("```")
        lines.append("Fix the error. Key P4-16 v1model rules:")
        lines.append("- Define ALL header types explicitly (ethernet_t, ipv4_t, etc. are NOT auto-imported)")
        lines.append("- Place all `typedef` statements before their first use")
        lines.append("- Use `bit<9>` for port numbers (PortId_t does not exist in v1model)")
        lines.append("- Express IP addresses as hex integers, not dotted notation")
        lines.append("- Deparser parameter must be `in H hdr`, not `inout`")
        lines.append("- Program must end with `V1Switch(...) main;`")
        return '\n'.join(lines)

    failures = [t for t in result.tests if t.result != 'PASS']
    if not failures:
        return ""

    lines.append(f"Compiled OK but {len(failures)} test(s) failed:")
    entry_errors = [t for t in failures if t.failure_type == 'ENTRY_INSTALL_ERROR']
    if entry_errors:
        detail = (entry_errors[0].detail or '')[:400]
        lines.append(f"entries.json action params don't match P4 action signatures: {detail}")
        lines.append("Ensure action_params keys/count exactly match the P4 action declaration.")
        lines.append("Use `\"action_params\": {}` for actions with no parameters.")
    for t in failures:
        if t.failure_type == 'ENTRY_INSTALL_ERROR':
            continue
        lines.append(f"- {t.name} ({t.failure_type}): {t.detail or ''}")
    return '\n'.join(lines)


class BenchmarkRunner:
    def __init__(self, adapter: LLMAdapter, engine: TestEngine = None):
        self.adapter = adapter
        self.engine = engine or TestEngine()

    def run_tasks(
        self,
        tasks_root: str,
        output_file: Optional[str] = None,
        task_type_filter: Optional[list] = None,
        verbose: bool = True,
        max_retries: int = 0,
        save_generated_dir: Optional[str] = None,
        meta: Optional[dict] = None,
        workers: int = 1,
        generate_only: bool = False,
    ) -> dict:
        """
        Run the benchmark on all tasks under tasks_root.

        With workers > 1, tasks are evaluated concurrently on a thread pool.
        This is safe because (a) the adapter is stateless — all per-call context
        is passed into generate() rather than held on the instance — and (b)
        each task's switch evaluation is fully isolated: SwitchRunner allocates a
        free Thrift port and a unique device-id per instance, and runs in its own
        temp dir (see evaluation/switch_runner.py). Work is I/O-bound (subprocess
        + sleep), so threads, not processes, give the speedup.

        Returns the aggregate report dict.
        """
        run_start = time.time()
        task_dirs = _discover_tasks(tasks_root)
        if not task_dirs:
            raise ValueError(f'No tasks found under {tasks_root}')

        # Resolve configs and apply filters up front, so the worker pool only
        # ever sees runnable tasks.
        pending = []  # (cfg, task_dir)
        for task_dir in task_dirs:
            try:
                cfg = TaskConfig(str(task_dir))
            except Exception as e:
                print(f'[SKIP] {task_dir}: cannot load task.yaml: {e}', file=sys.stderr)
                continue
            if task_type_filter and cfg.task_type not in task_type_filter:
                continue
            pending.append((cfg, task_dir))

        def _run(cfg, task_dir):
            if verbose:
                print(f'[RUN] {cfg.task_name}', file=sys.stderr)
            result = self._run_one_task(cfg, task_dir, max_retries,
                                        save_generated_dir=save_generated_dir,
                                        generate_only=generate_only)
            if verbose:
                status = 'PASS' if result.l3_score >= 1.0 else f'F={result.l3_score:.2f}'
                print(f'      [{cfg.task_name}] compiled={result.l1_compile} {status}', file=sys.stderr)
            return result

        n_workers = max(1, min(workers, len(pending))) if pending else 1
        if n_workers == 1:
            task_results = [_run(cfg, task_dir) for cfg, task_dir in pending]
        else:
            from concurrent.futures import ThreadPoolExecutor
            if verbose:
                print(f'[PARALLEL] {len(pending)} tasks on {n_workers} workers',
                      file=sys.stderr)
            with ThreadPoolExecutor(max_workers=n_workers) as pool:
                # Preserve task order in the report regardless of completion order.
                task_results = list(pool.map(lambda a: _run(*a), pending))

        report = self._aggregate(task_results)
        wall_time = round(time.time() - run_start, 2)
        if meta is not None:
            meta = dict(meta)
            meta.setdefault('wall_time_s', wall_time)
            report = {
                'schema_version': '2',
                'meta': meta,
                **report,
            }
        else:
            report['wall_time_s'] = wall_time
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f'Report written to {output_file}', file=sys.stderr)
        return report

    def _run_one_task(self, cfg: TaskConfig, task_dir: Path,
                      max_retries: int = 0, save_generated_dir: Optional[str] = None,
                      generate_only: bool = False) -> EvalResult:
        """Generate a solution and evaluate it, with feedback retries."""
        task_start = time.time()
        task_path = str(task_dir)

        def _stamp(result: EvalResult) -> EvalResult:
            result.task_path = task_path
            result.wall_time_s = round(time.time() - task_start, 2)
            return result

        prompt = build_prompt(cfg)
        best: EvalResult = None
        attempts_log: list = []
        total_attempts = 1 + max_retries
        feedback: Optional[str] = None  # threaded into generate() across retries

        for attempt in range(total_attempts):
            attempt_start = time.time()
            adapter_start = time.time()
            try:
                generated = self.adapter.generate(
                    prompt, cfg.task_type,
                    task_dir=str(task_dir), feedback=feedback,
                )
                adapter_time = round(time.time() - adapter_start, 2)
            except Exception as e:
                adapter_time = round(time.time() - adapter_start, 2)
                result = EvalResult(
                    task_name=cfg.task_name,
                    task_type=cfg.task_type,
                    l1_compile=False,
                    l1_error=f'Adapter error: {e}',
                )
                attempts_log.append({
                    'i': attempt + 1,
                    'l1_compile': False,
                    'l3_score': 0.0,
                    'l1_error_head': f'Adapter error: {e}'[:160],
                    'wall_time_s': round(time.time() - attempt_start, 2),
                    'adapter_time_s': adapter_time,
                })
                if best is None:
                    best = result
                break

            with tempfile.TemporaryDirectory(prefix='bmk_') as tmp:
                p4_path, entries_path = _assemble_full_program(
                    generated, task_dir, tmp
                )
                if save_generated_dir:
                    import shutil
                    save_dir = Path(save_generated_dir) / cfg.task_name
                    save_dir.mkdir(parents=True, exist_ok=True)
                    suffix = f'_attempt{attempt + 1}' if max_retries > 0 else ''
                    if p4_path and os.path.exists(p4_path):
                        shutil.copy(p4_path, save_dir / f'generated{suffix}.p4')
                    if entries_path and os.path.exists(entries_path):
                        shutil.copy(entries_path, save_dir / f'generated_entries{suffix}.json')
                if generate_only:
                    return _stamp(EvalResult(
                        task_name=cfg.task_name,
                        task_type=cfg.task_type,
                        l1_compile=False,
                        l1_error='generate-only: evaluation skipped',
                    ))
                result = self.engine.run(
                    task_dir=str(task_dir),
                    p4_file=p4_path,
                    entries_file=entries_path,
                )

            attempt_wall = round(time.time() - attempt_start, 2)
            attempts_log.append({
                'i': attempt + 1,
                'l1_compile': bool(result.l1_compile),
                'l3_score': round(result.l3_score, 4),
                'l1_error_head': (result.l1_error or '').splitlines()[0][:160] if result.l1_error else None,
                'wall_time_s': attempt_wall,
                'adapter_time_s': adapter_time,
                'engine_time_s': round(attempt_wall - adapter_time, 2),
            })

            # Keep best result
            if best is None or \
               (result.l1_compile and not best.l1_compile) or \
               (result.l1_compile == best.l1_compile and result.l3_score > best.l3_score):
                best = result

            if max_retries > 0:
                status = 'PASS' if result.l3_score >= 1.0 else f'F={result.l3_score:.2f}'
                print(f'      attempt {attempt + 1}/{total_attempts}: compiled={result.l1_compile} {status}',
                      file=sys.stderr)

            if result.l1_compile and result.l3_score >= 1.0:
                break  # perfect — no need to retry

            # Prepare feedback for next attempt (passed into the next
            # generate() call; adapters that ignore feedback simply drop it).
            if attempt < max_retries:
                feedback = _build_feedback(result) or None

        if best is not None:
            best.attempts = attempts_log
        return _stamp(best)

    def _aggregate(self, results: list[EvalResult]) -> dict:
        """Compute aggregate metrics across all task results."""
        if not results:
            return {'total_tasks': 0}

        total = len(results)
        l1_pass = sum(1 for r in results if r.l1_compile)
        l3_scores = [r.l3_score for r in results if r.l1_compile]

        def mean(lst):
            return round(sum(lst) / len(lst), 4) if lst else 0.0

        # By task type
        by_type = {}
        for t in ('full_program',):
            scores = [r.l3_score for r in results if r.task_type == t and r.l1_compile]
            if scores:
                by_type[t] = mean(scores)

        # Generalization gap
        pub_scores = [r.l3_public for r in results if r.l1_compile]
        hid_scores = [r.l3_hidden for r in results if r.l1_compile]
        gen_gap = round(mean(pub_scores) - mean(hid_scores), 4) if pub_scores else 0.0

        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_tasks': total,
            'l1_pass_rate': round(l1_pass / total, 4),
            'l3_mean': mean(l3_scores),
            'l3_by_task_type': by_type,
            'generalization_gap': gen_gap,
            'tasks': [r.to_dict() for r in results],
        }
