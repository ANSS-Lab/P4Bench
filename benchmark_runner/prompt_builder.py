"""Build the model-facing prompt for a task from its task.yaml."""
from evaluation.config_loader import TaskConfig


def _format_topology(cfg: TaskConfig) -> str:
    lines = ['**Switches:**']
    for sw in cfg.topology['switches']:
        ports_str = ', '.join(f'{k}=port{v}' for k, v in sw['ports'].items())
        lines.append(f'  - {sw["name"]} ({ports_str})')
    if cfg.topology.get('links'):
        lines.append('**Links:**')
        for link in cfg.topology['links']:
            lines.append(f'  - {link["from"]} <-> {link["to"]}')
    if cfg.hosts:
        lines.append('**Hosts:**')
        for h, info in cfg.hosts.items():
            role = info.get('role', '')
            role_str = f' ({role})' if role else ''
            # Only emit fields that are actually present — a missing ip/mac/port
            # is omitted rather than rendered as a fabricated '?'. Hosts that
            # carry only a free-text `note:` (address-transparent NFs, where the
            # decision-relevant addressing lives in the spec/test inputs, not in
            # host config) render the note instead of three blank unknowns.
            fields = [f'{label}={info[key]}'
                      for key, label in (('ip', 'IP'), ('mac', 'MAC'), ('port', 'port'))
                      if info.get(key) is not None]
            note = info.get('note')
            detail = ', '.join(fields)
            if detail and note:
                detail = f'{detail} ({note})'
            elif note:
                detail = note
            lines.append(f'  - {h}{role_str}: {detail}' if detail else f'  - {h}{role_str}')
    return '\n'.join(lines)


def _format_test_case(tc: dict) -> str:
    """Convert a test case to a natural language description."""
    desc = tc.get('description', tc['name'])
    inp = tc['input']
    expected = tc['expected']
    behavior = expected['behavior']

    lines = [f'- **{tc["name"]}**: {desc}']
    if behavior == 'drop':
        lines.append('  Expected: packet is DROPPED')
    else:
        port = expected.get('output_port', 'any port')
        lines.append(f'  Expected: packet forwarded out {port}')
        for field, spec in expected.get('transformations', {}).items():
            action = spec['action']
            if action == 'change_to':
                lines.append(f'    - {field} is rewritten to {spec["value"]}')
            elif action == 'change_to_set':
                lines.append(f'    - {field} is rewritten to one of {spec["values"]}')
            elif action == 'decremented_by':
                lines.append(f'    - {field} is decremented by {spec["delta"]}')
            elif action == 'incremented_by':
                lines.append(f'    - {field} is incremented by {spec["delta"]}')
            elif action == 'unchanged':
                lines.append(f'    - {field} is unchanged')
    return '\n'.join(lines)


FULL_PROGRAM_TEMPLATE = """\
You are a P4-16 network engineer. Write a complete P4 program and
its control-plane configuration for the BMv2 v1model architecture.

## Task
{description}

## Network Topology
{topology}

## Test Scenarios (your solution must handle these)
{test_scenarios}
{hints_section}
## Instructions
- Output a complete P4-16 program targeting BMv2 v1model.
- Output a control-plane configuration as JSON with table entries per switch.
- Use human-readable names for tables and actions.
- For ordinary P4 match-action tables, the entry format per switch is:
  [{{"table": "...", "match": {{...}}, "action_name": "...", "action_params": {{...}}}}]
- If your design needs BMv2 runtime resources that are not ordinary P4 table
  entries, use the extended per-switch object:
  {{
    "entries": [...],
    "multicast_groups": [{{"mgid": 1, "rid": 0, "ports": [2, 3]}}],
    "mirror_sessions": [{{"id": 100, "egress_port": 3}}],
    "action_profiles": [...]
  }}
- Use `multicast_groups` when the P4 sets `standard_metadata.mcast_grp`.
  Do not invent pseudo-tables such as `$pre.mcast_group`.
- Use `mirror_sessions` when the P4 calls `clone(...)` with a session id.
  Do not represent mirror sessions as normal `table_add` entries.

## Response Format

### program.p4
```p4
<your complete P4 program>
```

### entries.json
```json
<your control-plane entries per switch: {{"s1": [...]}} or {{"s1": {{"entries": [...], "multicast_groups": [...], "mirror_sessions": [...]}}}}>
```
"""


def build_prompt(cfg: TaskConfig) -> str:
    """Build the LLM prompt for a task."""
    public_tests = [tc for tc in cfg.test_cases if tc.get('visibility') == 'public']
    test_scenarios = '\n'.join(_format_test_case(tc) for tc in public_tests)
    topology_text = _format_topology(cfg)

    hints = cfg.hints
    hints_section = ''
    if hints:
        parts = ['## Hints']
        if hints.get('description'):
            parts.append(hints['description'].strip())
        if hints.get('p4_features'):
            parts.append(f'Suggested P4 features: {", ".join(hints["p4_features"])}')
        hints_section = '\n'.join(parts) + '\n\n'

    return FULL_PROGRAM_TEMPLATE.format(
        description=cfg.description.strip(),
        topology=topology_text,
        test_scenarios=test_scenarios,
        hints_section=hints_section,
    )
