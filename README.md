# P4Bench

**P4Bench: A Scalable and Adaptive Oracle-Backed Benchmark for P4 Programming
with Large Language Models** (POMACS / SIGMETRICS 2027).

P4Bench evaluates whether an LLM can produce a correct, deployable **P4-16**
network function: the model must generate both a data-plane program and the
matching control-plane table entries, and correctness is measured by deployed
packet behaviour on **BMv2 `simple_switch`** (v1model).

This repository contains the benchmark corpus and the evaluation harness:
- **130 tasks**
- **1,914 packet tests**
- **73 Task Pattern Language (TPL) patterns**

## Repository layout

- **`benchmark/<target_capability>/<task>/`**: the tasks, grouped by
  `target_capability`:

| target_capability | tasks |
|---|---|
| `redesign` | 42 |
| `scale_up` | 40 |
| `relocate` | 26 |
| `composition` | 22 |

  Each task ships `task.yaml` and, for tasks with non-standard headers,
  `custom_headers.py` (the Scapy layer definitions). `task.yaml` holds the
  model-facing specification, the topology, and the public and hidden test
  cases with their expected packet behaviour.
- **`evaluation/`**: the scoring engine. It runs the p4c compile gate, starts
  BMv2, installs entries over Thrift, and does packet I/O and verification.
- **`benchmark_runner/`**: batch orchestration. It builds the prompt from
  `task.yaml`, calls an adapter, scores the result, and writes a JSON report.
- **`adapters/`**: plug-ins for the models under test (see below).
- **`patterns/<P>/pattern.yaml`**: the TPL pattern each task instantiates,
  including its rules, invariants, parameters, mutation operators and source
  grounding.
- **`oracles/<P>/<hash>/oracle.py`**: the audited Python oracles, with their
  `audit_report.json`. Every test's expected output was derived from these
  oracles when the task was built, and stored in `task.yaml`. Scoring does
  **not** execute the oracles; they are shipped as the reference ground-truth
  semantics.
- **`dataset_index.json`**: a per-task manifest (pattern, the oracle its
  expected outputs were derived from, capability, number of public and hidden
  tests).
- **`tools/selftest.py`**: an integrity check that needs no LLM and no BMv2.

## Install

See **[INSTALL.md](INSTALL.md)**. In short:
1. `pip install -r requirements.txt`
2. Install the P4 toolchain: `p4c`, `simple_switch` and `simple_switch_CLI`.

## Run

```bash
# 1. Sanity check: every task parses and every test packet builds (no LLM, no BMv2)
python3 tools/selftest.py

# 2. Evaluate a model on the whole corpus
python3 -m benchmark_runner --adapter adapters/gpt_adapter.py --model <model> \
    --tasks benchmark/ --output results/<model>.json

# Single task
python3 -m benchmark_runner --adapter adapters/gpt_adapter.py --model <model> \
    --task benchmark/redesign/ipv4_routing_anchor

# Score an existing submission (P4 program + entries) against one task
python3 -m evaluation --task benchmark/redesign/ipv4_routing_anchor \
    --p4 my_solution.p4 --entries my_entries.json
```

Useful runner flags:
- `--workers N`: run tasks in parallel, each on an isolated switch.
- `--generate-only` plus `--save-generated DIR`: generate now and score later
  with `adapters/file_adapter.py` (`--adapter-opts root_dir=DIR`).
- `--max-retries N`: feedback-guided retries. Leave this at 0 to reproduce the
  paper's feedback-free protocol.

### Adapters

| Adapter | Models | Credentials |
|---|---|---|
| `adapters/gpt_adapter.py` | OpenAI GPT | `OPENAI_API_KEY` |
| `adapters/gemini_adapter.py` | Google Gemini | `GEMINI_API_KEY` |
| `adapters/claude_code_adapter.py` | Anthropic Claude (via the `claude` CLI) | Claude CLI login |
| `adapters/deepseek_adapter.py` | DeepSeek | `DEEPSEEK_API_KEY` |
| `adapters/qwen_adapter.py` | Qwen | `DASHSCOPE_API_KEY` |
| `adapters/file_adapter.py` | Replays previously generated files | none |

The adapters default to the settings used for the paper's results (all other
parameters, including reasoning/thinking settings and top-p, are left at the
provider defaults; override any of them with the environment variables listed
in each adapter's docstring):

| Model (paper) | Adapter `--model` | Temperature | Max output tokens |
|---|---|---|---|
| Opus-4.8 | `claude_code_adapter.py --model opus` (CLI, effort medium) | CLI default | 65,536 |
| Sonnet-4.6 | `claude_code_adapter.py --model claude-sonnet-4-6` (CLI, effort medium) | CLI default | 65,536 |
| GPT-5.5 | `gpt_adapter.py --model gpt-5.5` | default (fixed) | 65,536 |
| Gemini-3.1-Pro | `gemini_adapter.py --model gemini-3.1-pro-preview` | 0.8 | 65,536 |
| Qwen-3.7-Max | `qwen_adapter.py --model qwen3.7-max` | 0.8 | 65,536 |
| DeepSeek-V4-Pro | `deepseek_adapter.py --model deepseek-v4-pro` | 0.8 | 65,536 |

Each model was sampled with three independent draws per task (`--max-retries 0`).

To add your own model, subclass `adapters/base.py:LLMAdapter` and implement
`generate(prompt, task_type)`. It must return
`{"p4_code": str, "entries": dict | None}`.

Entries files are keyed by switch, for example:

```json
{"s1": [{"table": "MyIngress.ipv4_lpm",
          "match": {"hdr.ipv4.dstAddr": ["10.0.2.2", 32]},
          "action_name": "MyIngress.ipv4_forward",
          "action_params": {"dstAddr": "00:00:00:00:02:02", "port": 2}}]}
```

Tables and actions are matched by P4Info name, so a submission is free to
choose its own internal naming.

## Scoring

1. **Compilation gate.** `p4c --target bmv2 --arch v1model` must accept the
   program. If it does not, the attempt scores 0.
2. **Functional score F.** A value in [0, 1] computed from per-test pass rates,
   weighted **public 0.2 / hidden 0.8**. A submission that only satisfies the
   public examples can therefore score at most 0.2. Each test checks the
   behaviour (drop, forward or multicast), the egress port, and per-field
   packet transformations.
3. **Corpus metrics.** The paper uses k = 3 independent, feedback-free draws
   per task:
   - S₁ is the mean of F over the draws.
   - S₃ is the best F of the three draws.
   - Both are averaged over all tasks.
   - The compilation rate is the fraction of all generated programs that
     compile.

In the JSON reports, `l1_compile` is the compilation-gate result, `l3_score`
is F, and `l3_public` / `l3_hidden` are the public and hidden pass rates.

## Note on hidden tests

Because the corpus is public, the expected outputs of the hidden tests can be
read in `task.yaml`. The harness only sends a model the prompt built by
`benchmark_runner/prompt_builder.py`, which contains the specification and the
public examples. Do not give the model under test access to this repository
when you evaluate it.

## Citation

```bibtex
@article{gan2026p4bench,
  title   = {P4Bench: A Scalable and Adaptive Oracle-Backed Benchmark for P4 Programming with Large Language Models},
  author  = {Gan, Zirong and Liao, Shuyi and Niu, Yannian and Zheng, Xinyue and Yu, Tingting and Wang, Minmei},
  journal = {Proceedings of the ACM on Measurement and Analysis of Computing Systems},
  volume  = {10},
  number  = {3},
  year    = {2026}
}
```

## License

MIT. See [LICENSE](LICENSE).
