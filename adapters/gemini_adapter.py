"""
Gemini adapter for the benchmark runner.

Calls the Google Gemini API to generate P4 programs and control-plane entries.

Usage (CLI):
    python -m benchmark_runner \
        --adapter adapters/gemini_adapter.py \
        --model gemini-3.1-pro-preview \
        --tasks benchmark/ \
        --output results/gemini.json

Environment variables:
    GEMINI_API_KEY          Required. Your Google AI Studio API key.
    GEMINI_TEMPERATURE      Optional. Sampling temperature (default: 0.8).
    GEMINI_MAX_TOKENS       Optional. Max output tokens (default: 65536).

Paper setting: gemini-3.1-pro-preview via the Google GenAI API, temperature
0.8, 65,536 max output tokens.
"""
import json
import os
import re
import time

from adapters.base import LLMAdapter


def _extract_p4_code(text: str) -> str:
    """Concatenate every P4-tagged or untagged fenced block in the response.

    Mirrors adapters/claude_code_adapter._extract_p4_code: on harder tasks
    the model often splits its output into multiple fences (headers,
    ingress, deparser/main as separate blocks), and returning only the
    first fence yields a fragment that p4c rejects at line 1. Fences
    explicitly tagged as a different language (``json``, ``bash``, …)
    are skipped — those are commentary, not the program. Falls back to
    salvaging an unterminated opening fence if no closing fence is seen.
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
            else:
                if keep_block:
                    current.append(line)
    if blocks:
        return "\n\n".join("\n".join(b).strip() for b in blocks).strip()
    # Salvage an unterminated opening fence (truncated response).
    m = re.search(r'```(?:p4)?\s*\n(.*)$', text, re.DOTALL)
    if m:
        return m.group(1).strip()
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


class GeminiAdapter(LLMAdapter):
    """Calls the Google Gemini API via the google-genai SDK."""

    MAX_RETRIES = 3
    RETRY_BACKOFF = 2.0

    def __init__(self, model: str = "gemini-3.1-pro-preview"):
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "GEMINI_API_KEY or GOOGLE_API_KEY environment variable is required. "
                "Get a key at https://ai.google.dev"
            )

        try:
            from google import genai
        except ImportError:
            raise ImportError(
                "google-genai package is required. Install with: "
                "pip install google-genai"
            )

        self.client = genai.Client(api_key=api_key)
        self.model = model
        self.temperature = float(os.environ.get("GEMINI_TEMPERATURE", "0.8"))
        self.max_tokens = int(os.environ.get("GEMINI_MAX_TOKENS", "65536"))

    def generate(self, prompt: str, task_type: str, *,
                 task_dir: str = None, feedback: str = None) -> dict:
        from google.genai import types

        if feedback:
            prompt = (
                "## Feedback from Previous Attempt\n"
                "Your previous attempt had the following issues. "
                "Read them carefully and fix them in your new response.\n\n"
                f"{feedback}\n\n"
                "---\n\n"
            ) + prompt

        config = types.GenerateContentConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_tokens,
        )

        response_text = self._call_with_retry(prompt, config)


        p4_code = _extract_p4_code(response_text)
        entries = _extract_entries_json(response_text)
        return {"p4_code": p4_code, "entries": entries}

    def _call_with_retry(self, prompt: str, config) -> str:
        """Call Gemini API with exponential backoff on transient errors."""
        last_error = None
        for attempt in range(self.MAX_RETRIES):
            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=config,
                )
                if response.text:
                    return response.text
                raise RuntimeError(
                    f"Empty response from Gemini (finish_reason: "
                    f"{getattr(response.candidates[0], 'finish_reason', 'unknown')})"
                )
            except Exception as e:
                last_error = e
                err_str = str(e).lower()
                if "rate" in err_str or "429" in err_str or "503" in err_str:
                    wait = self.RETRY_BACKOFF * (2 ** attempt)
                    time.sleep(wait)
                    continue
                raise
        raise RuntimeError(
            f"Gemini API failed after {self.MAX_RETRIES} retries: {last_error}"
        )
