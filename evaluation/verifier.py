"""Verify captured output packets against expected test case behavior."""
import socket
from scapy.all import IP, TCP, UDP, Ether


def _get_field(pkt, field_path, custom_mod=None):
    """
    Get a field from a Scapy packet using dot-notation like 'IP.src', 'Ether.dst'.
    For indexed layers: 'layers[2].IP.src'
    """
    if field_path.startswith('layers['):
        # e.g. layers[4].IP.src — N is the 0-based STACK POSITION (not the Nth
        # occurrence of a class). Test authors index encapsulated stacks
        # positionally: layers[0]=outer Ether, [1]=outer IP, [2]=outer UDP,
        # [3]=VXLAN, [4]=inner Ether, [5]=inner IP, ...
        from scapy.packet import NoPayload
        idx_end = field_path.index(']')
        idx = int(field_path[7:idx_end])
        rest = field_path[idx_end + 2:]  # skip '].'
        layer_cls_name, field_name = rest.rsplit('.', 1)
        layer_cls = _resolve_layer_cls(layer_cls_name, custom_mod)
        # Walk the payload chain to the layer at stack position `idx`.
        layer = pkt
        for _ in range(idx):
            layer = layer.payload
        if layer is None or isinstance(layer, NoPayload):
            raise LookupError(
                f"Layer {layer_cls_name}[{idx}] not found in packet "
                f"(stack position {idx} out of range)")
        if not isinstance(layer, layer_cls):
            raise LookupError(
                f"Layer at stack position {idx} is "
                f"{type(layer).__name__}, expected {layer_cls_name}")
        return getattr(layer, field_name)

    layer_cls_name, field_name = field_path.rsplit('.', 1)
    layer_cls = _resolve_layer_cls(layer_cls_name, custom_mod)
    layer = pkt.getlayer(layer_cls)
    if layer is None:
        raise LookupError(f"Layer {layer_cls_name} not found in packet")
    return getattr(layer, field_name)


def _get_field_all(pkt, field_path, custom_mod=None):
    """Return the field value from EVERY occurrence of the layer in `pkt`
    (outermost first), for plain dot-notation paths. For indexed `layers[N]`
    paths, returns the single indexed value.

    Used to make `unchanged` / `decremented_by` / `incremented_by` baselines
    tunnel-aware: on a decap task the input carries both an outer and an inner
    IP, but `getlayer(IP)` returns only the outer, while the surviving output is
    the inner. Comparing the output against ANY input occurrence lets the inner
    baseline match without forcing every test author to spell out `layers[N]`.
    For single-layer (non-tunnel) packets this returns exactly one value, so
    behaviour is identical to the old single-occurrence read.
    """
    if field_path.startswith('layers['):
        return [_get_field(pkt, field_path, custom_mod)]
    layer_cls_name, field_name = field_path.rsplit('.', 1)
    layer_cls = _resolve_layer_cls(layer_cls_name, custom_mod)
    vals = []
    layer = pkt.getlayer(layer_cls)
    while layer is not None:
        vals.append(getattr(layer, field_name))
        nxt = layer.payload
        layer = nxt.getlayer(layer_cls) if nxt else None
    if not vals:
        raise LookupError(f"Layer {layer_cls_name} not found in packet")
    return vals


def _resolve_layer_cls(name, custom_mod=None):
    # Custom module takes priority — its bind_layers calls determine how the
    # output pcap is parsed, so the verifier must use the same class identity.
    if custom_mod is not None and hasattr(custom_mod, name):
        return getattr(custom_mod, name)
    from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP
    mapping = {'Ether': Ether, 'IP': IP, 'TCP': TCP, 'UDP': UDP, 'ICMP': ICMP, 'ARP': ARP}
    # Tunnel / overlay layers the encapsulation tasks assert on.
    try:
        from scapy.layers.vxlan import VXLAN
        mapping['VXLAN'] = VXLAN
    except Exception:
        pass
    try:
        from scapy.contrib.gtp import GTP_U_Header
        mapping['GTP_U_Header'] = GTP_U_Header
        mapping['GTPU'] = GTP_U_Header
    except Exception:
        pass
    if name in mapping:
        return mapping[name]
    raise ValueError(f"Unknown layer class: {name}")


def _normalize_value(val, field_path):
    """Normalize values for comparison (e.g. IP addresses to dotted notation)."""
    if isinstance(val, int) and 'IP.' in field_path and field_path.endswith(('src', 'dst')):
        return socket.inet_ntoa(val.to_bytes(4, 'big'))
    if isinstance(val, bytes) and 'Ether.' in field_path:
        return ':'.join(f'{b:02x}' for b in val)
    # Scapy's DNSStrField has an in-memory vs PCAP-parsed representation inconsistency:
    # in-memory construction gives b'foo.example.com' (no trailing dot) while
    # PCAP-parsed gives b'foo.example.com.' (with trailing dot = FQDN).
    # Strip the trailing dot to make comparisons consistent.
    if isinstance(val, bytes) and val.endswith(b'.') and 'qname' in field_path.lower():
        return val[:-1]
    return val


def verify_transformation(out_pkt, in_pkt, field_path, spec, custom_mod=None):
    """
    Check one transformation against the output packet.
    Returns (ok: bool, detail: str).
    """
    try:
        actual = _get_field(out_pkt, field_path, custom_mod)
        actual = _normalize_value(actual, field_path)
    except LookupError as e:
        return False, str(e)

    action = spec['action']

    if action == 'checksum_valid':
        # Recompute the layer's checksum over the OUTPUT packet and compare to
        # the emitted on-wire value. Deterministic regardless of residence —
        # catches a program that modified a payload (e.g. PTP correctionField
        # inside UDP) but left the stale checksum (bug taxonomy Cross-Cutting #1,
        # the #1 silent failure). `actual` (read above) is the emitted value.
        # Re-derive the checksum: clear it on a copy and let Scapy recompute on
        # rebuild, then reparse to read the computed value. Recompute is done on
        # the full packet so the L4 pseudo-header (IP src/dst) is correct.
        layer_cls_name, field_name = field_path.rsplit('.', 1)
        try:
            clone = out_pkt.__class__(bytes(out_pkt))   # fresh, independent copy
        except Exception as e:
            return False, f"{field_path}: could not clone output packet ({e})"
        # Support layers[N].Cls paths (same indexed-walk logic as _get_field)
        if layer_cls_name.startswith('layers['):
            from scapy.packet import NoPayload
            idx_end = layer_cls_name.index(']')
            idx = int(layer_cls_name[7:idx_end])
            real_cls_name = layer_cls_name[idx_end + 2:]  # skip '].'
            def _get_indexed_layer(pkt, idx, cls):
                layer = pkt
                for _ in range(idx):
                    layer = layer.payload
                return layer if isinstance(layer, cls) else None
            real_cls = _resolve_layer_cls(real_cls_name, custom_mod)
            target = _get_indexed_layer(clone, idx, real_cls)
            if target is None:
                return False, f"{field_path}: layer {layer_cls_name} not in output"
            setattr(target, field_name, None)
            rebuilt = clone.__class__(bytes(clone))
            recomputed = getattr(_get_indexed_layer(rebuilt, idx, real_cls), field_name)
        else:
            target = clone.getlayer(_resolve_layer_cls(layer_cls_name, custom_mod))
            if target is None:
                return False, f"{field_path}: layer {layer_cls_name} not in output"
            setattr(target, field_name, None)               # mark for recompute
            rebuilt = clone.__class__(bytes(clone))          # build (computes) + reparse
            recomputed = getattr(
                rebuilt.getlayer(_resolve_layer_cls(layer_cls_name, custom_mod)),
                field_name,
            )
        # A 0 checksum on IPv4 UDP nominally means "checksum disabled"; the task
        # requires recomputation, so a stale/zero value that disagrees with the
        # recomputed value is a failure.
        ok = (actual == recomputed)
        detail = (f"{field_path}: emitted {actual!r} vs recomputed {recomputed!r} "
                  f"({'valid' if ok else 'STALE — checksum not recomputed after payload edit'})")
        return ok, detail

    if action == 'change_to':
        expected = spec['value']
        # Numeric compare when the spec value is an int — coerces Scapy
        # FlagValue / enum-backed fields (e.g. VXLAN.flags is a FlagsField whose
        # value is 0x08 but str()s to a flag name) to their integer value.
        if isinstance(expected, int):
            try:
                ok = int(actual) == expected
                return ok, f"{field_path}: expected {expected}, got {int(actual)}"
            except (TypeError, ValueError):
                pass
        ok = str(actual) == str(expected)
        detail = f"{field_path}: expected {expected!r}, got {actual!r}"
        return ok, detail

    elif action == 'change_to_set':
        values = [str(v) for v in spec['values']]
        ok = str(actual) in values
        detail = f"{field_path}: expected one of {values}, got {actual!r}"
        return ok, detail

    elif action == 'change_to_range':
        ok = spec['min'] <= actual <= spec['max']
        detail = f"{field_path}: expected [{spec['min']},{spec['max']}], got {actual!r}"
        return ok, detail

    elif action == 'unchanged':
        try:
            originals = [_normalize_value(v, field_path)
                         for v in _get_field_all(in_pkt, field_path, custom_mod)]
        except LookupError:
            return False, f"{field_path}: could not read from input packet"
        # Tunnel-aware: the surviving (inner) header after decap is a different
        # IP occurrence than the outer one getlayer() returns — accept a match
        # against any input occurrence.
        ok = any(str(actual) == str(o) for o in originals)
        extra = f" (or inner {originals[1:]!r})" if len(originals) > 1 else ''
        detail = f"{field_path}: expected unchanged {originals[0]!r}{extra}, got {actual!r}"
        return ok, detail

    elif action == 'decremented_by':
        try:
            originals = _get_field_all(in_pkt, field_path, custom_mod)
        except LookupError:
            return False, f"{field_path}: could not read from input packet"
        candidates = [o - spec['delta'] for o in originals]
        ok = actual in candidates
        detail = (f"{field_path}: expected {originals[0]}-{spec['delta']}={candidates[0]}"
                  f"{' (or inner '+repr(candidates[1:])+')' if len(candidates) > 1 else ''}, "
                  f"got {actual!r}")
        return ok, detail

    elif action == 'incremented_by':
        try:
            originals = _get_field_all(in_pkt, field_path, custom_mod)
        except LookupError:
            return False, f"{field_path}: could not read from input packet"
        candidates = [o + spec['delta'] for o in originals]
        ok = actual in candidates
        detail = (f"{field_path}: expected {originals[0]}+{spec['delta']}={candidates[0]}"
                  f"{' (or inner '+repr(candidates[1:])+')' if len(candidates) > 1 else ''}, "
                  f"got {actual!r}")
        return ok, detail

    raise ValueError(f"Unknown transformation action: {action}")


def verify_test_case(test_case, in_pkt, received, port_resolver, custom_mod=None):
    """
    Verify a test case result.

    received: dict of {port_num: [scapy_pkt, ...]} — packets captured per port
    port_resolver: callable(port_spec) -> list[int] of acceptable port numbers

    Returns: (result, failure_type, detail)
      result: 'PASS' | 'FAIL'
      failure_type: None | 'UNEXPECTED_FORWARD' | 'UNEXPECTED_DROP' |
                    'WRONG_EGRESS_PORT' | 'WRONG_OUTPUT_FIELD' | 'CHECKSUM_ERROR'
    """
    expected = test_case['expected']
    behavior = expected['behavior']

    # Flatten all captured packets with their port
    all_captured = []
    for port_num, pkts in received.items():
        for p in pkts:
            all_captured.append((port_num, p))

    if behavior == 'drop':
        if all_captured:
            ports = [p for p, _ in all_captured]
            return 'FAIL', 'UNEXPECTED_FORWARD', f"Expected drop, got packet on port(s) {ports}"
        return 'PASS', None, ''

    # ── ECMP / multipath behaviours (behavioural, hash-agnostic) ──────────────
    # These reason over EVERY captured packet of a same-flow or multi-flow
    # burst (the engine hands the full non-input-port output set, not the
    # TTL-matched subset), so they verify the RFC 2992 properties without
    # leaking the hash the SUT must choose.
    if behavior in ('ecmp_consistent', 'ecmp_distributes'):
        members = set()
        for spec in expected.get('output_ports', []):
            members.update(port_resolver(spec))
        if not all_captured:
            return 'FAIL', 'UNEXPECTED_DROP', "Expected ECMP forward, no packet received"
        got_ports = {p for p, _ in all_captured}
        off_member = got_ports - members
        if off_member:
            return ('FAIL', 'WRONG_EGRESS_PORT',
                    f"ECMP packet(s) on non-member port(s) {sorted(off_member)}; "
                    f"group members are {sorted(members)}")

        if behavior == 'ecmp_consistent':
            # Every packet of one flow MUST land on the SAME next-hop
            # (RFC 2992 §2.2). A SUT that hashes a volatile field (TTL /
            # identification) splits the flow across members.
            if len(got_ports) != 1:
                return ('FAIL', 'ECMP_FLOW_SPLIT',
                        f"flow split across member ports {sorted(got_ports)} — "
                        f"the hash must use only stable 5-tuple fields")
            min_count = expected.get('min_count')
            if min_count is not None and len(all_captured) < min_count:
                return ('FAIL', 'UNEXPECTED_DROP',
                        f"only {len(all_captured)} of {min_count} flow packets forwarded")
            return 'PASS', None, ''

        # behavior == 'ecmp_distributes'
        # Distinct flows MUST spread across the group (the SUT actually
        # computes a hash, not a constant index).
        min_distinct = expected.get('min_distinct_ports', 2)
        if len(got_ports) < min_distinct:
            return ('FAIL', 'ECMP_NO_SPREAD',
                    f"distinct flows used only {sorted(got_ports)} "
                    f"({len(got_ports)} member(s)); expected ≥ {min_distinct} — "
                    f"the next-hop is not hash-distributed")
        return 'PASS', None, ''

    # behavior == 'forward'
    if not all_captured:
        return 'FAIL', 'UNEXPECTED_DROP', "Expected forward, no packet received"

    # Multi-port (multicast) form: expected.output_ports is a list.
    output_ports_spec = expected.get('output_ports')
    if output_ports_spec is not None:
        required = set()
        for spec in output_ports_spec:
            required.update(port_resolver(spec))
        got_ports = {p for p, _ in all_captured}
        missing = required - got_ports
        extra = got_ports - required
        if missing:
            return 'FAIL', 'WRONG_EGRESS_PORT', f"Missing output on ports {sorted(missing)}"
        if extra:
            return 'FAIL', 'WRONG_EGRESS_PORT', f"Unexpected output on ports {sorted(extra)}"
        # Verify transformations on every delivered copy.
        for port_num, out_pkt in all_captured:
            for field_path, spec in expected.get('transformations', {}).items():
                ok, detail = verify_transformation(out_pkt, in_pkt, field_path, spec, custom_mod)
                if not ok:
                    return 'FAIL', 'WRONG_OUTPUT_FIELD', f"port {port_num}: {detail}"
        return 'PASS', None, ''

    # Single-port form.
    output_port_spec = expected.get('output_port')
    if output_port_spec is not None:
        acceptable_ports = port_resolver(output_port_spec)
        # Prefer the packet on the expected port when multiple packets are
        # present (e.g. when prior_inputs went to a different port than the
        # test packet and both appear in all_captured).  This avoids a false
        # WRONG_EGRESS_PORT when a stateful warm-up packet happened to land
        # on a port that is not the expected output port.
        on_acceptable = [(p, pkt) for p, pkt in all_captured
                         if p in acceptable_ports]
        if on_acceptable:
            port_num, out_pkt = on_acceptable[0]
        else:
            port_num, out_pkt = all_captured[0]
            return (
                'FAIL', 'WRONG_EGRESS_PORT',
                f"Expected port in {acceptable_ports}, got port {port_num}"
            )
    else:
        port_num, out_pkt = all_captured[0]

    for field_path, spec in expected.get('transformations', {}).items():
        ok, detail = verify_transformation(out_pkt, in_pkt, field_path, spec, custom_mod)
        if not ok:
            return 'FAIL', 'WRONG_OUTPUT_FIELD', detail

    return 'PASS', None, ''
