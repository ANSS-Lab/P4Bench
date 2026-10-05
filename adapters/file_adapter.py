"""
File-based adapter for replaying pre-generated P4 programs and entries.

Use it for two-phase runs: first generate with
`python -m benchmark_runner ... --generate-only`, then score the saved files
without calling the model again.

Pass --adapter-opts root_dir=<path>, where <path> is the `generated/`
subdirectory of a generate-only run (e.g. results/runs/<run-id>/generated).
Reads: <root_dir>/<task_name>/generated.p4
       <root_dir>/<task_name>/generated_entries.json

Usage:
    python -m benchmark_runner \\
        --adapter adapters/file_adapter.py \\
        --model <model> \\
        --adapter-opts root_dir=results/runs/<run-id>/generated \\
        --tasks benchmark/
"""
import json
from pathlib import Path

from adapters.base import LLMAdapter


class FileAdapter(LLMAdapter):
    """
    Reads pre-generated artifacts from disk instead of calling an LLM:
      <root_dir>/<task_name>/generated.p4
      <root_dir>/<task_name>/generated_entries.json

    The runner passes task_dir to generate(); we extract the task name from
    it and look up the corresponding pre-generated files.
    """

    def __init__(self, model: str = None, root_dir: str = None):
        if not model:
            raise ValueError(
                'FileAdapter requires --model <name>.'
            )
        if not root_dir:
            raise ValueError(
                'FileAdapter requires --adapter-opts root_dir=<generated dir>.'
            )
        self.model = model
        self._root_dir = Path(root_dir)
        if not self._root_dir.exists():
            raise FileNotFoundError(
                f'root_dir does not exist: {self._root_dir}'
            )

    def generate(self, prompt: str, task_type: str, *,
                 task_dir: str = None, feedback: str = None) -> dict:
        if not task_dir:
            raise RuntimeError('FileAdapter.generate() requires task_dir')

        task_name = Path(task_dir).name
        task_out_dir = self._root_dir / task_name

        p4_file = task_out_dir / 'generated.p4'
        if not p4_file.exists():
            raise FileNotFoundError(
                f'Missing generated P4 for task "{task_name}" '
                f'(model: {self.model}).\n'
                f'Expected: {p4_file}'
            )
        p4_code = p4_file.read_text()

        entries_file = task_out_dir / 'generated_entries.json'
        if not entries_file.exists():
            raise FileNotFoundError(
                f'Missing entries file for task "{task_name}" '
                f'(model: {self.model}).\n'
                f'Expected: {entries_file}'
            )
        with open(entries_file) as f:
            entries = json.load(f)

        return {'p4_code': p4_code, 'entries': entries}
