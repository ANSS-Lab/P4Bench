"""
DeepSeek adapter for the benchmark runner.

Calls the DeepSeek API (OpenAI-compatible) to generate P4 programs and
control-plane entries.

Usage (CLI):
    python -m benchmark_runner \
        --adapter adapters/deepseek_adapter.py \
        --model deepseek-v4-pro \
        --tasks benchmark/ \
        --output results/deepseek.json

Environment variables:
    DEEPSEEK_API_KEY        Required. Your DeepSeek API key.
    DEEPSEEK_BASE_URL       Optional. API base URL (default: https://api.deepseek.com).
    DEEPSEEK_TEMPERATURE    Optional. Sampling temperature (default: 0.8;
                            fixed at 1 for deepseek-reasoner).
    DEEPSEEK_MAX_TOKENS     Optional. Max output tokens (default: 65536).

Paper setting: deepseek-v4-pro via the DeepSeek API, temperature 0.8,
65,536 max output tokens.

Models:
    deepseek-v4-pro     DeepSeek-V4 Pro (default; chat/coding, temperature supported)
    deepseek-chat       DeepSeek-V3 (chat/coding, temperature supported)
    deepseek-reasoner   DeepSeek-R1 (extended thinking; temperature fixed at 1)
"""
import json
import os
import re
import time

from adapters.base import LLMAdapter


def _extract_p4_code(text: str) -> str:
    """Concatenate every P4-tagged or untagged fenced block in the response.

    Multi-block extraction handles models that emit headers, ingress, and
    deparser as separate fenced blocks. Fences tagged as a different language
    (json, bash, …) are skipped. Falls back to salvaging an unterminated
    opening fence for truncated responses.
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
    m = re.search(r'```(?:p4)?\s*\n(.*)$', text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return text.strip()


def _extract_entries_json(text: str) -> dict | None:
    """Extract entries.json content from the response."""
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


class DeepSeekAdapter(LLMAdapter):
    """Calls the DeepSeek API via the openai SDK (OpenAI-compatible endpoint)."""

    MAX_RETRIES = 3
    RETRY_BACKOFF = 2.0

    def __init__(self, model: str = "deepseek-v4-pro"):
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "DEEPSEEK_API_KEY environment variable is required. "
                "Get a key at https://platform.deepseek.com/api_keys"
            )

        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package is required. Install with: pip install openai"
            )

        base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.max_tokens = int(os.environ.get("DEEPSEEK_MAX_TOKENS", "65536"))
        # deepseek-reasoner requires temperature=1; others default to 0.8
        default_temp = "1" if self._is_reasoner() else "0.8"
        self.temperature = float(os.environ.get("DEEPSEEK_TEMPERATURE", default_temp))

    def _is_reasoner(self) -> bool:
        return "reasoner" in self.model.lower()

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
        """Call DeepSeek API with exponential backoff on transient errors."""
        last_error = None
        for attempt in range(self.MAX_RETRIES):
            try:
                kwargs = dict(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                )
                response = self.client.chat.completions.create(**kwargs)
                choice = response.choices[0]
                # deepseek-reasoner exposes chain-of-thought in reasoning_content;
                # the final answer is always in message.content
                content = choice.message.content
                if content:
                    return content
                raise RuntimeError(
                    f"Empty response from DeepSeek "
                    f"(finish_reason: {choice.finish_reason})"
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
            f"DeepSeek API failed after {self.MAX_RETRIES} retries: {last_error}"
        )
