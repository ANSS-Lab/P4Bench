"""
Qwen (Alibaba DashScope) adapter for the benchmark runner.

Calls the DashScope OpenAI-compatible API to generate P4 programs and
control-plane entries. Qwen exposes an OpenAI-compatible endpoint, so this
adapter uses the `openai` SDK pointed at the DashScope `compatible-mode` base
URL — structurally identical to `gpt_adapter.py`.

Usage (CLI):
    python -m benchmark_runner \
        --adapter adapters/qwen_adapter.py \
        --model qwen3.7-max \
        --tasks benchmark/ \
        --output results/qwen.json

Environment variables:
    DASHSCOPE_API_KEY   Required. Your DashScope/Qwen API key (or QWEN_API_KEY).
    QWEN_BASE_URL       Optional. Override the compatible-mode base URL.
                        Default: the international endpoint
                          https://dashscope-intl.aliyuncs.com/compatible-mode/v1
                        For mainland-China accounts set:
                          https://dashscope.aliyuncs.com/compatible-mode/v1
    QWEN_TEMPERATURE    Optional. Sampling temperature (default: 0.8). >0 is
                        needed for diversity across the k independent draws.
    QWEN_MAX_TOKENS     Optional. Max output tokens (default: 65536).
    QWEN_ENABLE_THINKING  Optional. "true"/"false". For Qwen3 "thinking" models
                        on the compatible endpoint; left unset by default so
                        standard models (qwen-max/plus/turbo, qwen3-coder-*)
                        behave normally.

Paper setting: qwen3.7-max (resolved to snapshot qwen3.7-max-2026-06-08) via
the DashScope OpenAI-compatible endpoint, temperature 0.8, 65,536 max output
tokens.
"""
import json
import os
import re
import time

from adapters.base import LLMAdapter


def _extract_p4_code(text: str) -> str:
    """Extract P4 code from a markdown response.

    Concatenates every fenced block whose language tag is empty or starts with
    ``p4`` (``p4``, ``p416``, ``p4-16``, ...). On harder tasks the model often
    splits its output across multiple fences (headers, ingress body, deparser as
    separate blocks); returning only the first fence yields a fragment that p4c
    rejects at line 1. Fences explicitly tagged otherwise (``json``, ``bash``, ...)
    are skipped — those are commentary or the entries block, not the program.

    Ported from claude_code_adapter._extract_p4_code (line scanner, so a non-P4
    fence appearing before a P4 fence does not corrupt the match).
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
                keep_block = (tag == "" or tag.startswith("p4"))
                in_fence = True
                current = []
        else:
            if stripped.startswith("```"):
                if keep_block:
                    blocks.append(current)
                in_fence = False
                current = []
                keep_block = False
            elif keep_block:
                current.append(line)
    if blocks:
        # A genuine P4 fence carries structural tokens; a prose-only fence (e.g. an
        # ASCII wire diagram) has none and must be dropped so it is not concatenated
        # into the program. Fall back to all blocks if the filter leaves nothing.
        p4_blocks = [
            b for b in blocks
            if any(tok in line for line in b for tok in (";", "{", "}", "#"))
        ]
        chosen = p4_blocks or blocks
        return "\n\n".join("\n".join(b).strip() for b in chosen).strip()
    return text.strip()


def _extract_entries_json(text: str) -> dict | None:
    """Extract entries.json content from the response.

    Looks for a JSON code block after the P4 code block,
    or after an "entries.json" heading.
    """
    entries_section = re.split(
        r'#{1,3}\s*entries\.json', text, flags=re.IGNORECASE
    )
    search_text = entries_section[-1] if len(entries_section) > 1 else text

    json_blocks = re.findall(r'```(?:json)?\s*\n(.*?)```', search_text, re.DOTALL)

    for block in json_blocks:
        block = block.strip()
        try:
            parsed = json.loads(block)
            if isinstance(parsed, (dict, list)):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


class QwenAdapter(LLMAdapter):
    """Calls the DashScope OpenAI-compatible API via the openai SDK."""

    MAX_RETRIES = 3
    RETRY_BACKOFF = 2.0
    DEFAULT_BASE_URL = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"

    def __init__(self, model: str = "qwen3.7-max"):
        api_key = os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("QWEN_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "DASHSCOPE_API_KEY (or QWEN_API_KEY) environment variable is "
                "required. Get a key at "
                "https://dashscope.console.aliyun.com/apiKey"
            )

        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package is required. Install with: pip install openai"
            )

        base_url = os.environ.get("QWEN_BASE_URL", self.DEFAULT_BASE_URL)
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.temperature = float(os.environ.get("QWEN_TEMPERATURE", "0.8"))
        self.max_tokens = int(os.environ.get("QWEN_MAX_TOKENS", "65536"))

        thinking = os.environ.get("QWEN_ENABLE_THINKING")
        self.enable_thinking = (
            None if thinking is None else thinking.strip().lower() in ("1", "true", "yes")
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


        p4_code = _extract_p4_code(response_text)
        entries = _extract_entries_json(response_text)
        return {"p4_code": p4_code, "entries": entries}

    def _call_with_retry(self, prompt: str) -> str:
        """Call the DashScope API with exponential backoff on transient errors."""
        last_error = None
        for attempt in range(self.MAX_RETRIES):
            try:
                kwargs = dict(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                if self.enable_thinking is not None:
                    # Qwen3 thinking toggle is passed through extra_body on the
                    # OpenAI-compatible endpoint.
                    kwargs["extra_body"] = {"enable_thinking": self.enable_thinking}
                response = self.client.chat.completions.create(**kwargs)
                content = response.choices[0].message.content
                if content:
                    return content
                raise RuntimeError("Empty response from Qwen/DashScope")
            except Exception as e:
                last_error = e
                err_str = str(e).lower()
                if ("rate" in err_str or "429" in err_str or "503" in err_str
                        or "throttl" in err_str or "overload" in err_str):
                    wait = self.RETRY_BACKOFF * (2 ** attempt)
                    time.sleep(wait)
                    continue
                raise
        raise RuntimeError(
            f"Qwen/DashScope API failed after {self.MAX_RETRIES} retries: {last_error}"
        )
