# Installation

## 1. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
# then install only the adapter SDK(s) you need:
pip install openai          # for adapters/gpt_adapter.py
pip install google-genai    # for adapters/gemini_adapter.py
```

## 2. P4 toolchain (external — required to compile & run submissions)

The harness shells out to `p4c` (compile gate) and `simple_switch` +
`simple_switch_CLI` (BMv2 dataplane + Thrift entry installer).

**macOS (Homebrew):**
```bash
brew install p4lang/p4/p4c
brew install p4lang/p4/behavioral-model
```

**Ubuntu / other:** build from source —
- p4c:   https://github.com/p4lang/p4c
- BMv2:  https://github.com/p4lang/behavioral-model

## 3. Verify

```bash
p4c --version
which simple_switch simple_switch_CLI
python3 tools/selftest.py        # dataset + harness load (no toolchain needed)
```
