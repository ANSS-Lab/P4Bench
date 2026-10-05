"""
Testing engine: compile P4, run BMv2, install entries, execute test cases.

Uses simple_switch with --use-files (pcap) and Thrift CLI for entries.

Usage (Python API):
    engine = TestEngine()
    result = engine.run(task_dir, p4_file, entries_file)

Usage (CLI):
    python -m evaluation --task <path> --p4 <file> --entries <file>
"""
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

from scapy.all import IP, IPv6, TCP, UDP, ARP, Ether, conf as scapy_conf

from evaluation.config_loader import TaskConfig
from evaluation.packet_builder import build_packet, _load_custom_headers
from evaluation.verifier import verify_test_case
from evaluation.switch_runner import SwitchRunner, ThriftEntryInstaller
from evaluation.p4info_parser import P4InfoParser

_ROOT = Path(__file__).resolve().parent.parent
_ORACLE_INDEX = None


def _recorded_oracle(task_dir) -> Optional[str]:
    """The oracle path dataset_index.json records for this task, if any."""
    global _ORACLE_INDEX
    if _ORACLE_INDEX is None:
        _ORACLE_INDEX = {}
        try:
            with open(_ROOT / 'dataset_index.json') as f:
                for e in json.load(f):
                    if e.get('oracle'):
                        _ORACLE_INDEX[e['path']] = e['oracle']
        except (OSError, json.JSONDecodeError):
            pass
    try:
        rel = Path(task_dir).resolve().relative_to(_ROOT).as_posix()
    except ValueError:
        return None
    return _ORACLE_INDEX.get(rel)

scapy_conf.verb = 0


@dataclass
class TestResult:
    name: str
    visibility: str
    result: str          # 'PASS' | 'FAIL' | 'SKIPPED'
    failure_type: Optional[str] = None
    detail: str = ''


@dataclass
class EvalResult:
    task_name: str
    task_type: str
    l1_compile: bool
    l1_error: str = ''
    l3_score: float = 0.0
    l3_public: float = 0.0
    l3_hidden: float = 0.0
    tests: List[TestResult] = field(default_factory=list)
    # Provenance set by the runner
    task_path: str = ''
    wall_time_s: float = 0.0
    attempts: List[dict] = field(default_factory=list)
    # Oracle provenance; populated for pattern-instantiated tasks
    # (tasks that carry a `pattern:` field), otherwise None. Shape:
    #   {"pattern_id": str, "oracle_path": str | None,
    #    "audit_passed": bool | None, "warnings": list[str]}
    oracle_status: Optional[dict] = None

    def to_dict(self):
        d = {
            'task_name': self.task_name,
            'task_type': self.task_type,
            'l1_compile': self.l1_compile,
            'l1_error': self.l1_error,
            'l3_score': self.l3_score,
            'l3_public': self.l3_public,
            'l3_hidden': self.l3_hidden,
            'tests': [
                {
                    'name': t.name,
                    'visibility': t.visibility,
                    'result': t.result,
                    'failure_type': t.failure_type,
                    'detail': t.detail,
                }
                for t in self.tests
            ],
        }
        if self.task_path:
            d['task_path'] = self.task_path
        if self.wall_time_s:
            d['wall_time_s'] = round(self.wall_time_s, 2)
        if self.attempts:
            d['attempts'] = self.attempts
        if self.oracle_status is not None:
            d['oracle_status'] = self.oracle_status
        return d


def _ip_any(layer_or_pkt):
    """Innermost IPv4 *or* IPv6 layer, or None. Family-agnostic counterpart of
    `getlayer(IP)`: a cross-family translator (NAT64, 464XLAT) emits an output
    whose IP family differs from the input's, so a v4-only lookup returns None
    and the packet is attributed to nothing."""
    v4, v6 = layer_or_pkt.getlayer(IP), layer_or_pkt.getlayer(IPv6)
    if v4 is None:
        return v6
    if v6 is None:
        return v4
    # Both present (e.g. 6-in-4): the innermost one is the deeper in the stack.
    return v6 if bytes(v6) in bytes(v4) else v4


def _inner_ip(pkt):
    """Return the innermost IP layer of `pkt` (the one that survives tunnel
    decap and that the verifier grades), or None. Handles IPv4 and IPv6. For a
    single-IP packet this is just that IP, so behaviour is identical to
    `pkt.getlayer(IP)` for the non-tunnel IPv4 case."""
    l = _ip_any(pkt)
    while l is not None and l.payload is not None:
        deeper = _ip_any(l.payload)
        if deeper is None:
            break
        l = deeper
    return l


def _ip_proto(l):
    """L4 protocol number, family-agnostic (IPv4 `proto` / IPv6 `nh`)."""
    return l.nh if isinstance(l, IPv6) else l.proto


def _ip_ttl(l):
    """Hop count, family-agnostic (IPv4 `ttl` / IPv6 `hlim`)."""
    return l.hlim if isinstance(l, IPv6) else l.ttl


def _same_family(a, b):
    return isinstance(a, IPv6) == isinstance(b, IPv6)


def _src_anchor_ok(in_pkt, pkt, proto, anchor):
    """True if `pkt` matches `in_pkt` on the chosen IP/L4 anchor.

    anchor='src': output preserves source (IP.src + L4 sport) — the default.
    anchor='dst': output preserves destination (IP.dst + L4 dport) — used as a
    fallback for SNAT tasks, where the NF correctly rewrites the source so no
    output can match IP.src, but the destination is preserved.
    anchor='reflect': output is a reflected reply addressed back to the sender —
    IP.src == in.dst and IP.dst == in.src (endpoint swap). Used as a last-resort
    fallback for hairpin reply protocols (e.g. BFD Poll/Final, ICMP echo reply)
    where a correct NF emits the response back toward the peer, swapping both
    endpoints so neither the src nor the dst anchor can attribute it. L4 ports
    are not constrained here (reflection port semantics are protocol-specific).
    anchor='xlat': output is a CROSS-FAMILY translation of the input (v6->v4 or
    v4->v6, e.g. NAT64/464XLAT). Neither address anchor can survive, because the
    NF rewrites both endpoints into the other family's address space. Matched on
    family-change + L4 protocol, preferring an output that preserves one L4
    port. Last-resort: only reached when src/dst/reflect all fail.

    Both sides are read from the INNERMOST IP/L4 layer, so a GTP-U / VXLAN decap
    test (whose forwarded output is the inner packet) anchors on the inner
    addresses that actually survive, not the tunnel endpoints. The IP-address
    half is required; the L4-port half is checked only for TCP/UDP.
    """
    in_ip, out_ip = _inner_ip(in_pkt), _inner_ip(pkt)
    if in_ip is None or out_ip is None:
        return False
    if anchor == 'xlat':
        # Only ever engages across a family change; same-family traffic must
        # still be attributed by a real address anchor.
        return not _same_family(in_ip, out_ip)
    if anchor == 'reflect':
        return out_ip.src == in_ip.dst and out_ip.dst == in_ip.src
    if anchor == 'src':
        if out_ip.src != in_ip.src:
            return False
        attr = 'sport'
    else:
        if out_ip.dst != in_ip.dst:
            return False
        attr = 'dport'
    in_l4 = in_ip.getlayer(TCP) or in_ip.getlayer(UDP)
    out_l4 = out_ip.getlayer(TCP) or out_ip.getlayer(UDP)
    if proto in (6, 17) and in_l4 is not None and out_l4 is not None:
        return getattr(out_l4, attr) == getattr(in_l4, attr)
    return True


def _find_matching_output(in_pkt, output_pkts_by_port):
    """
    Find an output packet that corresponds to the input packet.

    Matching strategy (most-specific first):
      - IP.src must match
      - IP.proto must match
      - L4 sport must match (for TCP/UDP)
      - Output IP.ttl must be in {in_ttl-1, in_ttl} (TTL decrement tiebreaker)

    The TTL constraint disambiguates test cases that share the same 5-tuple
    but have different TTLs (e.g. TTL=64 vs TTL=1 with the same sport).

    Returns (port_num, pkt) or None.
    """
    if _inner_ip(in_pkt) is None:
        # ARP: prior_inputs may also be ARP packets, so etherType alone cannot
        # disambiguate.  Match on (psrc, hwsrc) which the NF spec guarantees is
        # unique between test packet and priors.
        if ARP in in_pkt:
            in_psrc = in_pkt[ARP].psrc
            in_hwsrc = in_pkt[ARP].hwsrc
            for port_num, pkts in output_pkts_by_port.items():
                for pkt in pkts:
                    if ARP in pkt and pkt[ARP].psrc == in_psrc and pkt[ARP].hwsrc == in_hwsrc:
                        return port_num, pkt
            return None
        # Non-IP input (e.g. custom probe header): match by outer
        # etherType — prior_inputs for stateful tests are usually plain IPv4
        # (etherType 0x0800) while the packet under test carries a distinctive
        # custom etherType, which disambiguates it from warm-up outputs.
        in_etype = in_pkt[Ether].type if Ether in in_pkt else None
        if in_etype is None:
            return None
        for port_num, pkts in output_pkts_by_port.items():
            for pkt in pkts:
                if Ether in pkt and pkt[Ether].type == in_etype:
                    return port_num, pkt
        return None

    in_ip = _inner_ip(in_pkt)
    proto = _ip_proto(in_ip)
    in_ttl = _ip_ttl(in_ip)
    # Accept output TTL of in_ttl or in_ttl-1 (accounting for decrement)
    acceptable_ttls = {max(0, in_ttl - 1), in_ttl}

    def _scan(anchor):
        for port_num, pkts in output_pkts_by_port.items():
            for pkt in pkts:
                out_ip = _inner_ip(pkt)
                if out_ip is None:
                    continue
                if _ip_proto(out_ip) != proto:
                    continue
                # A reflected reply is ORIGINATED by the NF, not forwarded, so
                # its TTL is protocol-mandated (e.g. BFD demands 255) and bears
                # no relation to the input's. Applying the forward-path TTL
                # window here rejects correct replies (multi-hop BFD Poll:
                # in_ttl=200, mandated reply TTL=255).
                if anchor != 'reflect' and _ip_ttl(out_ip) not in acceptable_ttls:
                    continue
                if _src_anchor_ok(in_pkt, pkt, proto, anchor):
                    return port_num, pkt
        return None

    # Primary: anchor on source (src IP + sport) — the historical behaviour,
    # unchanged for non-NAT tasks. Fallback: if SNAT rewrote the source so no
    # output matches it, anchor on the preserved destination (dst IP + dport).
    # Then a reflected reply (endpoint swap) — hairpin Poll/Final etc. Last:
    # a cross-family translation (NAT64), where no address anchor can survive.
    return _scan('src') or _scan('dst') or _scan('reflect') or _scan('xlat')


def _find_all_matching_outputs(in_pkt, output_pkts_by_port):
    """Return {port_num: [pkt,...]} for every output packet that matches the
    test packet. Used for multicast/flood tests with prior_inputs."""
    result = {}
    if _inner_ip(in_pkt) is None:
        if ARP in in_pkt:
            in_psrc = in_pkt[ARP].psrc
            in_hwsrc = in_pkt[ARP].hwsrc
            for port_num, pkts in output_pkts_by_port.items():
                for pkt in pkts:
                    if ARP in pkt and pkt[ARP].psrc == in_psrc and pkt[ARP].hwsrc == in_hwsrc:
                        result.setdefault(port_num, []).append(pkt)
            return result
        in_etype = in_pkt[Ether].type if Ether in in_pkt else None
        if in_etype is None:
            return {}
        for port_num, pkts in output_pkts_by_port.items():
            for pkt in pkts:
                if Ether in pkt and pkt[Ether].type == in_etype:
                    result.setdefault(port_num, []).append(pkt)
        return result

    in_ip = _inner_ip(in_pkt)
    proto = _ip_proto(in_ip)
    in_ttl = _ip_ttl(in_ip)
    acceptable_ttls = {max(0, in_ttl - 1), in_ttl}

    def _scan(anchor):
        res = {}
        for port_num, pkts in output_pkts_by_port.items():
            for pkt in pkts:
                out_ip = _inner_ip(pkt)
                if out_ip is None or _ip_proto(out_ip) != proto:
                    continue
                # See _find_matching_output: an originated reply's TTL is
                # protocol-mandated, not inherited from the input.
                if anchor != 'reflect' and _ip_ttl(out_ip) not in acceptable_ttls:
                    continue
                if _src_anchor_ok(in_pkt, pkt, proto, anchor):
                    res.setdefault(port_num, []).append(pkt)
        return res

    # Primary: source anchor (unchanged for non-NAT tasks). Fallback to the
    # destination anchor only when SNAT rewrote the source so nothing matches,
    # then to a reflected-reply anchor (endpoint swap) for hairpin Poll/Final,
    # then to a cross-family (NAT64) translation where no address anchor holds.
    return _scan('src') or _scan('dst') or _scan('reflect') or _scan('xlat')


class TestEngine:
    """Compile P4 and run functional tests using BMv2 pcap file mode."""

    def run(
        self,
        task_dir: str,
        p4_file: str = None,
        entries_file: str = None,
    ) -> EvalResult:
        cfg = TaskConfig(task_dir)

        result = EvalResult(
            task_name=cfg.task_name,
            task_type=cfg.task_type,
            l1_compile=False,
        )

        # Oracle provenance check: for pattern-instantiated tasks, confirm an
        # audited Python oracle exists under oracles/<pattern_id>/. The
        # expected: blocks in task.yaml were derived from that oracle when the
        # task was built; this check makes sure they are backed by an audited
        # oracle. Failures are warnings, not errors — the engine always grades
        # against the expected: blocks.
        if cfg.has_pattern:
            result.oracle_status = self._check_oracle_provenance(cfg)

        # ── Compile gate ──────────────────────────────────────────────────────
        with tempfile.TemporaryDirectory(prefix='p4eval_') as tmp:
            ok, bmv2_json, p4info_txt, err = self._compile(p4_file, tmp)
            result.l1_compile = ok
            result.l1_error = err
            if not ok:
                return result

            budget = cfg.constraints.get('max_register_cells')
            if budget is not None:
                used, over = self._check_register_budget(bmv2_json, budget)
                if over:
                    result.l1_compile = False
                    result.l1_error = (
                        f'register memory budget exceeded: '
                        f'used {used} cells, max allowed {budget}'
                    )
                    return result

            # ── Functional correctness ─────────────────────────────────────────
            entries = self._load_entries(entries_file)
            p4info = P4InfoParser(p4info_txt)
            test_results = self._run_functional_tests(cfg, bmv2_json, p4info, entries)
            result.tests = test_results
            result.l3_public, result.l3_hidden, result.l3_score = (
                self._compute_l3_scores(test_results, cfg)
            )

        return result

    # ── Compilation ────────────────────────────────────────────────────────────

    def _compile(self, p4_file, out_dir):
        stem = Path(p4_file).stem
        p4info_out = os.path.join(out_dir, f'{stem}.p4info.txt')

        cmd = [
            'p4c',
            '--target', 'bmv2',
            '--arch', 'v1model',
            '--std', 'p4-16',
            '--p4runtime-files', p4info_out,
            '-o', out_dir,
            p4_file,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            return False, None, None, r.stderr.strip()

        # Find produced .json
        candidates = list(Path(out_dir).glob('*.json'))
        if not candidates:
            return False, None, None, 'p4c produced no .json output'

        return True, str(candidates[0]), p4info_out, ''

    # ── Oracle provenance check ───────────────────────────────────────────────

    def _check_oracle_provenance(self, cfg) -> dict:
        """Verify a pattern-instantiated task has a passing audited oracle.

        Returns a dict suitable for EvalResult.oracle_status:
            {pattern_id, oracle_path, audit_passed, warnings}

        The check is informational. The engine continues with the static
        expected: blocks in task.yaml regardless. Oracles are content-addressed
        at oracles/<pattern_id>/<sha256[:8]>/; the task's oracle is the one
        dataset_index.json records for it, and tasks
        absent from the index fall back to the first passing oracle found
        under oracles/<pattern_id>/.
        """
        import sys

        status = {
            'pattern_id':   cfg.pattern_id,
            'oracle_path':  None,
            'audit_passed': None,
            'warnings':     [],
        }

        oracles_root = _ROOT / 'oracles' / cfg.pattern_id
        if not oracles_root.exists():
            status['warnings'].append(
                f"no oracles/{cfg.pattern_id}/ directory found; "
                "static expected: blocks not provenance-verified"
            )
            print(f"[engine] WARN: {status['warnings'][-1]}", file=sys.stderr)
            return status

        # Find any oracle.py whose audit_report.json reports passing checks.
        recorded = _recorded_oracle(cfg.task_dir)
        candidates = []
        for sub in sorted(oracles_root.iterdir()):
            if not sub.is_dir():
                continue
            oracle_py = sub / 'oracle.py'
            audit_json = sub / 'audit_report.json'
            if not oracle_py.exists():
                continue
            audit_passed = None
            if audit_json.exists():
                try:
                    with open(audit_json) as f:
                        audit = json.load(f)
                    audit_passed = bool(
                        audit.get('passed') or
                        audit.get('status') == 'passed' or
                        audit.get('overall') == 'passed' or
                        audit.get('audit_passed') is True
                    )
                except (json.JSONDecodeError, OSError):
                    audit_passed = None
            candidates.append((sub, oracle_py, audit_passed))

        if recorded:
            match = [c for c in candidates
                     if c[1].relative_to(_ROOT).as_posix() == recorded]
            if not match:
                status['warnings'].append(
                    f"oracle {recorded} recorded in dataset_index.json "
                    "not found; static expected: blocks not provenance-verified"
                )
                print(f"[engine] WARN: {status['warnings'][-1]}", file=sys.stderr)
                return status
            candidates = match

        if not candidates:
            status['warnings'].append(
                f"oracles/{cfg.pattern_id}/ has no oracle.py — "
                "task has a `pattern:` field but no oracle is registered"
            )
            print(f"[engine] WARN: {status['warnings'][-1]}", file=sys.stderr)
            return status

        # Prefer a passing audited oracle; fall back to the first candidate.
        passing = [c for c in candidates if c[2] is True]
        chosen = passing[0] if passing else candidates[0]
        sub, oracle_py, audit_passed = chosen
        status['oracle_path']  = oracle_py.relative_to(_ROOT).as_posix()
        status['audit_passed'] = audit_passed

        if audit_passed is None:
            status['warnings'].append(
                f"oracle at {status['oracle_path']} has no audit_report.json — "
                "audit status unknown"
            )
            print(f"[engine] WARN: {status['warnings'][-1]}", file=sys.stderr)
        elif not audit_passed:
            status['warnings'].append(
                f"oracle at {status['oracle_path']} did not pass audit — "
                "static expected: blocks may not match the spec"
            )
            print(f"[engine] WARN: {status['warnings'][-1]}", file=sys.stderr)
        elif len(candidates) > 1 and len(passing) > 1:
            status['warnings'].append(
                f"oracles/{cfg.pattern_id}/ has multiple passing oracles and "
                "dataset_index.json records none for this task; chose "
                f"{status['oracle_path']} by sort order"
            )
            print(f"[engine] INFO: {status['warnings'][-1]}", file=sys.stderr)

        return status

    # ── Register memory budget ─────────────────────────────────────────────────

    def _check_register_budget(self, bmv2_json_path, budget):
        with open(bmv2_json_path) as f:
            data = json.load(f)
        used = sum(int(r.get('size', 0)) for r in data.get('register_arrays', []))
        return used, used > budget

    # ── Entry loading ───────────────────────────────────────────────────────────

    def _load_entries(self, entries_file):
        if not entries_file or not os.path.exists(entries_file):
            return {}
        with open(entries_file) as f:
            data = json.load(f)
        if isinstance(data, list):
            return {'s1': data}
        return data

    # ── Functional testing ──────────────────────────────────────────────────────

    def _run_functional_tests(self, cfg, bmv2_json, p4info, entries):
        """
        Run each test case in its own switch invocation to avoid packet ambiguity.

        Each test:
          1. Write one input packet to the switch's port pcap
          2. Start switch, install entries, let it process
          3. Read all output pcap files
          4. Verify the single output (or lack of one) against expected behavior
        """
        sw_cfg = cfg.get_switch()
        switch_name = sw_cfg['name']

        def port_resolver(port_spec):
            return cfg.resolve_port_numbers(port_spec)

        passed_tests = set()
        results = []

        for tc in cfg.test_cases:
            name = tc['name']
            vis = tc.get('visibility', 'public')

            # Check depends_on
            dep = tc.get('depends_on')
            if dep and dep not in passed_tests:
                tr = TestResult(name, vis, 'SKIPPED', None,
                                f"Dependency '{dep}' did not pass")
                results.append(tr)
                continue

            try:
                tr = self._run_one_test_case(
                    tc, cfg, sw_cfg, switch_name,
                    bmv2_json, p4info, entries, port_resolver
                )
            except Exception as exc:
                tr = TestResult(name, vis, 'ERROR', 'harness_error', str(exc))
            results.append(tr)
            if tr.result == 'PASS':
                passed_tests.add(name)

        return results

    def _run_one_test_case(self, tc, cfg, sw_cfg, switch_name,
                           bmv2_json, p4info, entries, port_resolver):
        """Run a single test case with its own switch instance."""
        name = tc['name']
        vis = tc.get('visibility', 'public')

        in_pkt = build_packet(tc['input'], task_dir=str(cfg.task_dir))
        input_port = cfg.get_input_port_num(tc['input']['port'])

        # Build prior (warm-up) packets for stateful tests.
        # prior_inputs are sent before the main test packet so that register
        # state (e.g., sketch counters) accumulates before the packet under test.
        # The main test packet should use a distinct TTL so _find_matching_output
        # can identify its output among any warm-up outputs.
        all_input_pkts = {}  # port_num -> [pkts]
        # When prior_inputs are present, assign pcap timestamps so that across
        # different port files BMv2 still processes prior_inputs before the
        # main test packet. Same-port ordering already works via list order
        # within one pcap. When there are no prior_inputs, leave timestamps
        # untouched (default) to avoid disturbing non-stateful tests.
        priors = tc.get('prior_inputs', [])
        if priors:
            t = 0.0
            for pi in priors:
                pi_port = cfg.get_input_port_num(pi['port'])
                pi_pkt = build_packet(pi, task_dir=str(cfg.task_dir))
                pi_pkt.time = t
                t += 0.01
                all_input_pkts.setdefault(pi_port, []).append(pi_pkt)
            in_pkt.time = max(t, 0.5)
        all_input_pkts.setdefault(input_port, []).append(in_pkt)

        with tempfile.TemporaryDirectory(prefix='p4tc_') as work_dir:
            runner = SwitchRunner(sw_cfg, bmv2_json)
            runner.setup(work_dir)
            runner.prepare_inputs(all_input_pkts)
            runner.start(startup_wait=1.5)

            try:
                ThriftEntryInstaller.install(
                    entries, switch_name, runner.thrift_port, p4info
                )
            except Exception as e:
                runner.stop(wait_for_output=False)
                return TestResult(name, vis, 'FAIL', 'ENTRY_INSTALL_ERROR', str(e))

            runner.stop(wait_for_output=True)
            all_outputs = runner.read_all_outputs()

        # Determine which ports the test expects output on (for multicast tests
        # that send back to the ingress port, we must NOT exclude the input port).
        expected_output_port_nums = set()
        exp = tc.get('expected', {})
        if exp.get('output_ports'):
            for spec in exp['output_ports']:
                expected_output_port_nums.update(port_resolver(spec))
        # Singular form: a forward test may legitimately egress its INGRESS port
        # (hairpin — e.g. a route whose next-hop is reachable via the arrival
        # port). Honour `output_port` (singular) too, else the input-port
        # exclusion below wrongly drops the correct output (false UNEXPECTED_DROP).
        if exp.get('output_port'):
            expected_output_port_nums.update(port_resolver(exp['output_port']))

        # Exclude the input port from candidates unless the test explicitly
        # expects output on it (e.g. multicast that loops back to ingress).
        output_ports = {
            p: pkts for p, pkts in all_outputs.items()
            if (p != input_port or p in expected_output_port_nums) and pkts
        }

        # When prior_inputs are present the pcap contains warm-up packet outputs
        # as well as the test packet output.  Use _find_matching_output to isolate
        # only the output corresponding to the test packet (the test packet must
        # use a TTL distinct from warm-up packets so TTL-based matching works).
        if tc.get('expected', {}).get('behavior') in ('ecmp_consistent', 'ecmp_distributes'):
            # Behavioural multipath checks reason over the WHOLE burst (a
            # same-flow burst for consistency, or many distinct flows for
            # distribution), so hand the verifier every output on a
            # non-input port rather than the single test-packet match.
            received = {p: pkts for p, pkts in output_ports.items()}
        elif tc.get('prior_inputs'):
            # Collect outputs that match the test packet.  The test packet is
            # always submitted LAST (highest timestamp), so among a set of
            # indistinguishable packets (same src/proto/sport/TTL) on a given
            # port the test-packet output is the LAST one.  Keeping only the
            # last match per port discards warm-up (prior_input) outputs that
            # share the same IP/L4 signature, while still supporting multicast
            # where the test packet legitimately appears on several output ports.
            #
            # Count how many prior_inputs were submitted on each port — this
            # bounds how many outputs on that port can be attributed to prior
            # processing (priors arriving on port P may also produce output on
            # OTHER ports via multicast/flood, but this per-port count is the
            # most precise bound we can compute without re-running the oracle).
            # If outputs on port P exceed both (a) what the test packet could
            # cause and (b) what priors could have caused via ingress on P, we
            # report unexpected forward; otherwise treat as prior-induced output.
            priors_per_port = {}
            for pi in priors:
                pp = cfg.get_input_port_num(pi['port'])
                priors_per_port[pp] = priors_per_port.get(pp, 0) + 1
            # Total priors submitted (upper bound on prior-caused outputs on
            # any single non-input port via multicast from ANY ingress port).
            total_priors = len(priors)

            all_matches = _find_all_matching_outputs(in_pkt, output_ports)
            received = {}
            for port, pkts in all_matches.items():
                if not pkts:
                    continue
                # How many outputs on this port can be attributed to priors?
                # Use total_priors as the ceiling (a multicast from any prior
                # can produce at most 1 copy per port, so total_priors is the
                # conservative upper bound).
                prior_budget = total_priors
                if len(pkts) <= prior_budget:
                    # All outputs on this port are plausibly from prior
                    # processing.  For a forward test, the test packet's output
                    # is the LAST one (highest timestamp); if all copies are
                    # within the prior budget we still use the last to support
                    # the common case where priors don't touch this port and
                    # the single match is genuinely from the test packet.
                    # For a drop test, the budget check already means we
                    # should see nothing extra — handled below.
                    received[port] = [pkts[-1]]
                else:
                    # More outputs than priors could explain — the test packet
                    # forwarded here too; keep the extras (the last N - budget).
                    received[port] = pkts[prior_budget:]

            # For DROP tests: any port whose output count is fully within the
            # prior budget should NOT appear in received (the test produced
            # nothing there).  Remove such ports so the verifier sees an empty
            # received set and correctly reports PASS for drop.
            if exp.get('behavior') == 'drop':
                received = {
                    port: pkts for port, pkts in received.items()
                    if len(all_matches.get(port, [])) > total_priors
                }
        else:
            received = {p: pkts for p, pkts in output_ports.items()}

        custom_mod = _load_custom_headers(str(cfg.task_dir))
        result_str, failure_type, detail = verify_test_case(
            tc, in_pkt, received, port_resolver, custom_mod=custom_mod
        )
        return TestResult(name, vis, result_str, failure_type, detail)

    # ── Score computation ───────────────────────────────────────────────────────

    def _compute_l3_scores(self, test_results, cfg):
        pub = [t for t in test_results if t.visibility == 'public']
        hid = [t for t in test_results if t.visibility == 'hidden']

        pub_pass = sum(1 for t in pub if t.result == 'PASS')
        hid_pass = sum(1 for t in hid if t.result == 'PASS')

        pub_score = pub_pass / len(pub) if pub else 1.0
        hid_score = hid_pass / len(hid) if hid else 1.0
        l3 = cfg.public_weight * pub_score + cfg.hidden_weight * hid_score

        return round(pub_score, 4), round(hid_score, 4), round(l3, 4)


if __name__ == '__main__':
    from evaluation.__main__ import main
    main()
