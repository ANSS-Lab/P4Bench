"""Build Scapy packets from task.yaml test_case input specs."""
import importlib.util
import sys
from pathlib import Path

from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, ARP, Raw,
    conf as scapy_conf,
)
scapy_conf.verb = 0


_custom_headers_cache = {}


def _load_custom_headers(task_dir):
    """Import custom_headers.py from task directory if present.

    Cached per absolute task_dir so that repeated calls return the same
    module instance — critical because scapy's bind_layers registers the
    module's classes with the global layer table, and verifier queries
    via getlayer(cls) must use the same class identity.
    """
    p = (Path(task_dir) / 'custom_headers.py').resolve()
    if not p.exists():
        return None
    key = str(p)
    if key in _custom_headers_cache:
        return _custom_headers_cache[key]
    mod_name = f'custom_headers_{abs(hash(key))}'
    spec = importlib.util.spec_from_file_location(mod_name, p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    _custom_headers_cache[key] = mod
    return mod


_LAYER_MAP = {
    'Ether': Ether,
    'IP': IP,
    'TCP': TCP,
    'UDP': UDP,
    'ICMP': ICMP,
    'ARP': ARP,
    'Raw': Raw,
}


def _build_layer(layer_name, fields, custom_mod=None):
    if custom_mod and hasattr(custom_mod, layer_name):
        cls = getattr(custom_mod, layer_name)
    elif layer_name in _LAYER_MAP:
        cls = _LAYER_MAP[layer_name]
    else:
        try:
            from scapy import layers as scapy_layers
            cls = getattr(scapy_layers.all, layer_name)
        except AttributeError:
            raise ValueError(f"Unknown layer: {layer_name}")

    clean = {}
    for k, v in fields.items():
        if k == 'load_hex':
            # Raw payloads are stored hex-encoded in task.yaml so the YAML stays clean;
            # decode back to the bytes scapy's `load` field expects.
            clean['load'] = bytes.fromhex(v)
            continue
        if isinstance(v, str) and v.startswith('0x'):
            v = int(v, 16)
        clean[k] = v
    return cls(**clean)


def build_packet(input_spec, task_dir=None):
    """
    Build a Scapy packet from the input spec in task.yaml.

    Supports Level B (layers list) and Level C (scapy expression).
    Returns the Scapy packet.
    """
    custom_mod = _load_custom_headers(task_dir) if task_dir else None

    # Level C: raw Scapy expression
    if 'scapy' in input_spec:
        ns = dict(_LAYER_MAP)
        if custom_mod:
            for name in dir(custom_mod):
                if not name.startswith('_'):
                    ns[name] = getattr(custom_mod, name)
        return eval(input_spec['scapy'], ns)  # noqa: S307

    # Level B: explicit layer stack
    if 'layers' in input_spec:
        pkt = None
        for layer_spec in input_spec['layers']:
            for layer_name, fields in layer_spec.items():
                layer = _build_layer(layer_name, fields, custom_mod)
                pkt = layer if pkt is None else pkt / layer
        return pkt

    raise ValueError("input_spec must have 'layers' or 'scapy' key")
