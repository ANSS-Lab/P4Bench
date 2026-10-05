"""
Claude Code adapter for the benchmark runner.

Invokes the `claude` CLI in non-interactive print mode (`-p`) to generate
P4 programs and control-plane entries. This avoids the need for an
Anthropic API key — the CLI uses whichever auth the user has already
configured (Claude subscription login, ANTHROPIC_API_KEY, etc.).

Modes (selected via --adapter-opts agent_mode=<bool>):
    pure (default)   — CLI runs with `--tools ""` and no slash commands;
                       model outputs text only, no tool use.
    agent            — CLI runs with all built-in tools and permissions bypassed;
                       the model can compile, run scripts, read files, etc.

Usage (CLI):
    # Pure mode
    python -m benchmark_runner \
        --adapter adapters/claude_code_adapter.py \
        --model opus \
        --tasks benchmark/ \
        --output results/claude.json

    # Agent mode
    python -m benchmark_runner \
        --adapter adapters/claude_code_adapter.py \
        --model opus \
        --adapter-opts agent_mode=true \
        --tasks benchmark/ \
        --output results/claude_agent.json

Environment variables:
    CLAUDE_CLI_PATH         Optional. Path to the claude binary (default: 'claude' on PATH).
    CLAUDE_CLI_TIMEOUT      Optional. Per-call timeout in seconds (default: 600 pure, 1800 agent).
    CLAUDE_CLI_EXTRA_ARGS   Optional. Extra args appended to the claude invocation
                            (space-separated, shell-split).
    CLAUDE_CODE_MAX_OUTPUT_TOKENS
                            Optional. Max output tokens for the CLI (default: 65536).
    CLAUDE_BENCHMARK_EFFORT Optional. CLI effort level (default: medium).

Paper setting: Opus-4.8 via `--model opus` (the CLI alias, which resolved to
Opus 4.8 at evaluation time) and Sonnet-4.6 via `--model claude-sonnet-4-6`,
pure mode (no tools), effort medium, CLI-default temperature, 65,536 max
output tokens.
"""
import json
import os
import re
import shlex
import subprocess
import time

from adapters.base import LLMAdapter


def _extract_p4_code(text: str) -> str:
    """Extract P4 code from a markdown response.

    Concatenates every fenced block whose language tag is empty or
    starts with ``p4`` (``p4``, ``p416``, ``p4-16``, ...). On harder
    tasks the model often splits its output into multiple fences
    (headers, ingress body, deparser+main as separate blocks);
    returning only the first fence yields a fragment that p4c rejects
    at line 1. Fences explicitly tagged as a different language
    (``json``, ``bash``, ...) are skipped — those are commentary, not
    the program.

    Uses a line scanner instead of a single regex so that a non-P4
    fence appearing before a P4 fence does not corrupt the match.
    """
    blocks: list[list[str]] = []
    in_fence = False
    keep_block = False
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if not in_fence:
            if stripped.startswith("```"):
                tag = stripped[3:].strip().lower()
                # Untagged fence ⇒ keep; tag starts with "p4" ⇒ keep;
                # any other tag (json, bash, python, …) ⇒ skip.
                keep_block = (tag == "" or tag.startswith("p4"))
                in_fence = True
                current = []
            # Else: prose line, ignore.
        else:
            if stripped.startswith("```"):
                if keep_block:
                    blocks.append(current)
                in_fence = False
                current = []
                keep_block = False
            else:
                if keep_block:
                    current.append(line)
    if blocks:
        # A genuine P4 fence carries structural tokens (``;``, ``{``, ``}``).
        # A fence holding only prose — e.g. an ASCII wire-format diagram the
        # model emits as commentary — has none, and must be dropped: otherwise
        # it is concatenated into the program and p4c rejects the whole file
        # at the diagram line. Fall back to every block if the filter would
        # leave nothing (defensive — a real program always has structure).
        p4_blocks = [
            b for b in blocks
            if any(tok in line for line in b for tok in (";", "{", "}"))
        ]
        chosen = p4_blocks or blocks
        return "\n\n".join("\n".join(b).strip() for b in chosen).strip()
    return text.strip()


def _extract_entries_json(text: str) -> dict | None:
    """Extract entries.json content from the response."""
    entries_section = re.split(
        r'#{1,3}\s*entries\.json', text, flags=re.IGNORECASE
    )
    search_text = entries_section[-1] if len(entries_section) > 1 else text

    json_blocks = re.findall(r'```(?:json)?\s*\n(.*?)```', search_text, re.DOTALL)
    for block in json_blocks:
        try:
            parsed = json.loads(block.strip())
            if isinstance(parsed, (dict, list)):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


class ClaudeCodeAdapter(LLMAdapter):
    """Calls the Claude Code CLI (`claude -p`) as a subprocess."""

    MAX_RETRIES = 3
    RETRY_BACKOFF = 2.0

    def __init__(self, model: str = "opus", agent_mode: bool = False):
        self.cli_path = os.environ.get("CLAUDE_CLI_PATH", "claude")
        self.model = model
        self.agent_mode = bool(agent_mode)

        default_timeout = "1800" if self.agent_mode else "600"
        self.timeout = int(os.environ.get("CLAUDE_CLI_TIMEOUT", default_timeout))

        extra = os.environ.get("CLAUDE_CLI_EXTRA_ARGS", "")
        self.extra_args = shlex.split(extra) if extra else []

        # Verify the CLI is reachable at startup so failures happen early.
        try:
            subprocess.run(
                [self.cli_path, "--version"],
                capture_output=True, text=True, timeout=10, check=True,
            )
        except FileNotFoundError:
            raise EnvironmentError(
                f"Claude CLI not found at '{self.cli_path}'. "
                "Install it from https://docs.claude.com/claude-code or set "
                "CLAUDE_CLI_PATH to the binary location."
            )
        except subprocess.CalledProcessError as e:
            raise EnvironmentError(
                f"Claude CLI failed version check: {e.stderr or e.stdout}"
            )

    def generate(self, prompt: str, task_type: str, *,
                 task_dir: str = None, feedback: str = None) -> dict:
        if feedback:
            prompt = (
                "## Feedback from Previous Attempt\n"
                "Your previous attempt had the following issues. "
                "Read them carefully and fix them in your new response.\n\n"
                f"{feedback}\n\n"
                "---\n\n"
            ) + prompt

        response_text = self._call_with_retry(prompt)


        return {
            "p4_code": _extract_p4_code(response_text),
            "entries": _extract_entries_json(response_text),
        }

    def _build_cmd(self) -> list[str]:
        cmd = [
            self.cli_path,
            "-p",                         # print mode (non-interactive)
            "--output-format", "text",
            "--model", self.model,
            "--no-session-persistence",
            # Pin the effort level so wall-time is comparable across runs;
            # without this the subprocess inherits CLAUDE_EFFORT from the
            # caller's env (e.g. a high effort level), causing extended
            # multi-round thinking that can push a single call past 30+ min.
            "--effort", os.environ.get("CLAUDE_BENCHMARK_EFFORT", "medium"),
        ]
        if self.agent_mode:
            # Agent mode: enable the default toolset and pre-approve the tools
            # the model needs to author + compile + iterate on a P4 program.
            # We use --allowedTools rather than --permission-mode
            # bypassPermissions because the latter maps to
            # --dangerously-skip-permissions, which the CLI refuses to run
            # under root/sudo. In -p (non-interactive) mode there is no TTY to
            # answer a permission prompt, so any tool not on this allow-list is
            # auto-denied — the list must be explicit.
            cmd += [
                "--tools", "default",
                "--allowedTools",
                "Bash Edit Write Read Glob Grep MultiEdit NotebookEdit",
            ]
        else:
            # Pure mode: no tools, no skills — text generation only.
            cmd += [
                "--tools", "",
                "--disable-slash-commands",
            ]
        cmd.extend(self.extra_args)
        return cmd

    def _call_with_retry(self, prompt: str) -> str:
        cmd = self._build_cmd()
        last_error = None
        # Run the CLI from /tmp so that Claude Code's project-file discovery
        # (CLAUDE.md, project memory, .claude/skills/) does NOT load anything
        # from the benchmark checkout into the model-under-test's context.
        # Otherwise a call made from inside this repository could see task
        # files (including hidden-test expectations), contaminating results.
        run_cwd = "/tmp"
        run_env = dict(os.environ)
        run_env.setdefault("CLAUDE_CODE_MAX_OUTPUT_TOKENS", "65536")
        for attempt in range(self.MAX_RETRIES):
            try:
                result = subprocess.run(
                    cmd,
                    input=prompt,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                    cwd=run_cwd,
                    env=run_env,
                )
                if result.returncode != 0:
                    err = (result.stderr or result.stdout).strip()
                    raise RuntimeError(
                        f"claude CLI exited {result.returncode}: {err}"
                    )
                content = result.stdout.strip()
                if not content:
                    raise RuntimeError("Empty response from claude CLI")
                return content
            except subprocess.TimeoutExpired as e:
                last_error = e
                wait = self.RETRY_BACKOFF * (2 ** attempt)
                time.sleep(wait)
                continue
            except RuntimeError as e:
                last_error = e
                err_str = str(e).lower()
                if any(tok in err_str for tok in ("rate", "429", "503", "overloaded")):
                    wait = self.RETRY_BACKOFF * (2 ** attempt)
                    time.sleep(wait)
                    continue
                raise
        raise RuntimeError(
            f"claude CLI failed after {self.MAX_RETRIES} retries: {last_error}"
        )
