"""Load and validate task.yaml, resolve port names to numbers."""
from pathlib import Path
import yaml


class TaskConfig:
    """Parsed and resolved task configuration."""

    def __init__(self, task_dir):
        self.task_dir = Path(task_dir)
        task_yaml = self.task_dir / 'task.yaml'
        with open(task_yaml) as f:
            self._raw = yaml.safe_load(f)

        self.task_name = self._raw['task_name']
        self.task_type = self._raw['task_type']
        self.complexity = self._raw['complexity']
        self.source = self._raw['source']
        self.description = self._raw['description']
        self.test_cases = self._raw['test_cases']
        self.topology = self._raw['topology']
        self.hosts = self._raw.get('hosts', {})
        self.hints = self._raw.get('hints', {})
        self.constraints = self._raw.get('constraints', {})
        scoring = self._raw.get('scoring', {})
        # Functional score weights: public 0.2 / hidden 0.8 — the
        # asymmetry rewards generalisation, so a submission overfitting the
        # public examples cannot score above 0.2 on functional correctness.
        self.public_weight = scoring.get('public_weight', 0.2)
        self.hidden_weight = scoring.get('hidden_weight', 0.8)

        # Build port name -> port number lookup: "s1.client" -> (switch_name, port_num)
        self._port_map = {}  # "s1.client" -> (switch_idx, port_num)
        self._switch_by_name = {}
        for sw in self.topology['switches']:
            self._switch_by_name[sw['name']] = sw
            for port_name, port_num in sw['ports'].items():
                key = f"{sw['name']}.{port_name}"
                self._port_map[key] = (sw['name'], port_num)

    def resolve_port(self, port_spec):
        """
        Resolve a port spec to a list of (switch_name, port_num) tuples.

        port_spec can be:
          - "s1.client"        -> [(s1, 1)]
          - ["s1.b1","s1.b2"] -> [(s1,2),(s1,3)]
        """
        if isinstance(port_spec, list):
            return [self._port_map[p] for p in port_spec]
        return [self._port_map[port_spec]]

    def resolve_port_numbers(self, port_spec):
        """Return list of port numbers (int) for a port spec."""
        return [pn for _, pn in self.resolve_port(port_spec)]

    def get_switch(self, name=None):
        """Return first switch config, or the named one."""
        if name:
            return self._switch_by_name[name]
        return self.topology['switches'][0]

    def get_input_port_num(self, port_spec):
        """Resolve a single input port spec to a port number."""
        ports = self.resolve_port_numbers(port_spec)
        if len(ports) != 1:
            raise ValueError(f"Expected single input port, got {ports} for {port_spec!r}")
        return ports[0]

    @property
    def pattern_field(self):
        """Raw `pattern:` field from task.yaml, or None if absent.

        For pattern-instantiated TPL tasks the field is either a string
        like "P-StatefulLB-v2" or "P-StatefulLB-v2@1.0".
        """
        return self._raw.get('pattern')

    @property
    def has_pattern(self) -> bool:
        """True iff this task is pattern-instantiated (carries `pattern:`)."""
        return self.pattern_field is not None

    @property
    def pattern_id(self):
        """The pattern_id portion of the `pattern:` field, stripped of @version."""
        p = self.pattern_field
        if p is None:
            return None
        return p.split('@', 1)[0]
