"""Parse P4Info protobuf text file and resolve names to IDs/bitwidths."""
import socket
import math
from google.protobuf import text_format
from p4.config.v1 import p4info_pb2


class P4InfoParser:
    def __init__(self, p4info_path):
        with open(p4info_path) as f:
            content = f.read()
        p4info = p4info_pb2.P4Info()
        text_format.Merge(content, p4info)

        self._tables = {}   # name -> table proto
        self._actions = {}  # name -> action proto

        for t in p4info.tables:
            self._tables[t.preamble.name] = t
        for a in p4info.actions:
            self._actions[a.preamble.name] = a

    def get_table_id(self, name):
        return self._tables[name].preamble.id

    def get_match_field(self, table_name, field_name):
        for mf in self._tables[table_name].match_fields:
            if mf.name == field_name:
                return mf
        raise KeyError(f"Match field '{field_name}' not in table '{table_name}'")

    def get_match_kind(self, table_name, field_name):
        """Return the field's match kind as a lowercase string
        ('exact'|'lpm'|'ternary'|'range'|'optional'), or None if the table /
        field is unknown. Lets the entry installer format each match value by
        its declared match_kind instead of guessing from the value shape — a
        `range` field's [lo, hi] must render as `lo->hi`, not ternary `v&&&m`."""
        try:
            mf = self.get_match_field(table_name, field_name)
        except KeyError:
            return None
        which = mf.WhichOneof('match')
        if which == 'match_type':
            return p4info_pb2.MatchField.MatchType.Name(mf.match_type).lower()
        if which == 'other_match_type':
            return mf.other_match_type.lower()
        return None

    def get_action_id(self, name):
        return self._actions[name].preamble.id

    def get_action_param(self, action_name, param_name):
        for p in self._actions[action_name].params:
            if p.name == param_name:
                return p
        raise KeyError(f"Param '{param_name}' not in action '{action_name}'")

    def encode_value(self, value, bitwidth):
        """Encode a value as big-endian bytes of ceil(bitwidth/8) length."""
        nbytes = math.ceil(bitwidth / 8)
        if isinstance(value, str):
            parts = value.split('.')
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return socket.inet_aton(value)
            if ':' in value and len(value.split(':')) == 6:
                return bytes.fromhex(value.replace(':', ''))
            return int(value).to_bytes(nbytes, 'big')
        if isinstance(value, int):
            return value.to_bytes(nbytes, 'big')
        raise ValueError(f"Cannot encode {value!r} for bitwidth {bitwidth}")
