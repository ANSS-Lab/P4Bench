"""
GPT adapter for the benchmark runner.

Calls the OpenAI API to generate P4 programs and control-plane entries.

Usage (CLI):
    python -m benchmark_runner \
        --adapter adapters/gpt_adapter.py \
        --model gpt-5.5 \
        --tasks benchmark/ \
        --output results/gpt.json

Environment variables:
    OPENAI_API_KEY          Required. Your OpenAI API key.
    OPENAI_TEMPERATURE      Optional. Sampling temperature (default: 0.8). Not
                            sent for gpt-5.5, which only accepts its default.
    OPENAI_MAX_TOKENS       Optional. Max output tokens (default: 65536).

Paper setting: gpt-5.5 via Chat Completions, default (fixed) temperature,
65,536 max output tokens.
"""
import json
import os
import re
import time

from adapters.base import LLMAdapter


def _extract_p4_code(text: str) -> str:
    """Extract the first P4 code block from a markdown response."""
    pattern = re.compile(r'```(?:p4)?\s*\n(.*?)```', re.DOTALL)
    match = pattern.search(text)
    if match:
        return match.group(1).strip()
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


class GPTAdapter(LLMAdapter):
    """Calls the OpenAI API via the openai SDK."""

    MAX_RETRIES = 3
    RETRY_BACKOFF = 2.0

    def __init__(self, model: str = "gpt-5.5"):
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "OPENAI_API_KEY environment variable is required. "
                "Get a key at https://platform.openai.com/api-keys"
            )

        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package is required. Install with: "
                "pip install openai"
            )

        base_url = os.environ.get("OPENAI_BASE_URL", "https://us.api.openai.com/v1")
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.temperature = float(os.environ.get("OPENAI_TEMPERATURE", "0.8"))
        if not self._supports_temperature():
            self.temperature = None   # model only accepts its default temperature
        self.max_tokens = int(os.environ.get("OPENAI_MAX_TOKENS", "65536"))

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

    def _is_codex_model(self) -> bool:
        return "codex" in self.model.lower()

    def _supports_temperature(self) -> bool:
        # gpt-5.5 and some o-series models only accept the default temperature
        no_temp = {"gpt-5.5", "o1", "o1-mini", "o1-preview", "o3", "o3-mini", "o4-mini"}
        return self.model not in no_temp and not self.model.startswith("o1") and not self.model.startswith("o3")

    def _call_with_retry(self, prompt: str) -> str:
        """Call OpenAI API with exponential backoff on transient errors."""
        last_error = None
        for attempt in range(self.MAX_RETRIES):
            try:
                if self._is_codex_model():
                    response = self.client.responses.create(
                        model=self.model,
                        input=prompt,
                    )
                    content = response.output_text
                else:
                    kwargs = dict(
                        model=self.model,
                        messages=[{"role": "user", "content": prompt}],
                        max_completion_tokens=self.max_tokens,
                    )
                    if self._supports_temperature():
                        kwargs["temperature"] = self.temperature
                    response = self.client.chat.completions.create(**kwargs)
                    content = response.choices[0].message.content
                if content:
                    return content
                raise RuntimeError("Empty response from OpenAI")
            except Exception as e:
                last_error = e
                err_str = str(e).lower()
                if "rate" in err_str or "429" in err_str or "503" in err_str:
                    wait = self.RETRY_BACKOFF * (2 ** attempt)
                    time.sleep(wait)
                    continue
                raise
        raise RuntimeError(
            f"OpenAI API failed after {self.MAX_RETRIES} retries: {last_error}"
        )
