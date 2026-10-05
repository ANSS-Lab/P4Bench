"""
BMv2 simple_switch runner using pcap file I/O and Thrift CLI for entries.

Uses simple_switch with --use-files mode:
  - Input packets are written to {port}_in.pcap files
  - Output packets are read from {port}_out.pcap files
  - Table entries are installed via simple_switch_CLI (Thrift)
"""
import os
import random
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from scapy.all import wrpcap, rdpcap, Ether, conf as scapy_conf

scapy_conf.verb = 0

# How long simple_switch waits before processing pcap files
USE_FILES_DELAY = 3   # seconds (must exceed startup_wait + thrift install time)


class ThriftEntryInstaller:
    """Convert entries.json entries to simple_switch_CLI Thrift commands."""

    @staticmethod
    def _ip_to_int(ip_str):
        packed = socket.inet_aton(ip_str)
        return struct.unpack('!I', packed)[0]

    @staticmethod
    def _format_value(val):
        """Format an action param / match value for Thrift CLI."""
        if isinstance(val, str):
            parts = val.split('.')
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                # IPv4 → decimal integer
                return str(ThriftEntryInstaller._ip_to_int(val))
            # MAC or other string — pass through
            return val
        return str(val)

    @staticmethod
    def _switch_section(entries_per_switch, switch_name):
        """Normalize the per-switch entry to
        (entries_list, multicast_groups_list, mirror_sessions_list,
         action_profiles_list).

        Accepts either the plain shape (a list of entries) or the extended shape
        ({"entries": [...], "multicast_groups": [...], "mirror_sessions": [...],
          "action_profiles": [...]}).
        """
        sec = entries_per_switch.get(switch_name, [])
        if isinstance(sec, list):
            return sec, [], [], []
        return (
            sec.get('entries', []),
            sec.get('multicast_groups', []),
            sec.get('mirror_sessions', []),
            sec.get('action_profiles', []),
        )

    @classmethod
    def _format_match(cls, entry, p4info_parser=None):
        """Build the `table_add` match-field string for an entry and report
        whether it carries a priority (ternary / range / optional). Shared by
        direct and indirect (action-profile / selector) entries.

        A 2-element list `[a, b]` is ambiguous on its own — it could be a
        range (`a->b`), an lpm `a/b`, or a ternary `a&&&b`. When a
        `p4info_parser` is supplied we disambiguate each field by its declared
        match_kind (the authoritative source); otherwise we fall back to the
        priority heuristic (priority present → ternary, else lpm) for
        backward compatibility."""
        is_ternary = 'priority' in entry
        table = entry.get('table')
        match_parts = []
        for fname, field_val in entry.get('match', {}).items():
            kind = (p4info_parser.get_match_kind(table, fname)
                    if p4info_parser else None)
            # Explicit tagged forms always win regardless of match_kind.
            if isinstance(field_val, dict) and 'range' in field_val:
                lo, hi = field_val['range']
                match_parts.append(
                    f'{cls._format_value(lo)}->{cls._format_value(hi)}')
            elif isinstance(field_val, dict) and 'ternary' in field_val:
                v, m = field_val['ternary']
                match_parts.append(
                    f'{cls._format_value(v)}&&&{cls._format_value(m)}')
            elif isinstance(field_val, list):
                if kind == 'range':
                    lo, hi = field_val
                    match_parts.append(
                        f'{cls._format_value(lo)}->{cls._format_value(hi)}')
                elif kind == 'lpm':
                    ip, plen = field_val
                    match_parts.append(f'{ip}/{plen}')
                elif kind == 'ternary':
                    v, m = field_val
                    match_parts.append(
                        f'{cls._format_value(v)}&&&{cls._format_value(m)}')
                elif is_ternary:           # no p4info: priority => ternary
                    v, m = field_val
                    match_parts.append(
                        f'{cls._format_value(v)}&&&{cls._format_value(m)}')
                else:                      # no p4info, no priority => lpm
                    ip, plen = field_val
                    match_parts.append(f'{ip}/{plen}')
            else:
                match_parts.append(cls._format_value(field_val))
        return ' '.join(match_parts), is_ternary

    @classmethod
    def build_cli_commands(cls, entries_per_switch, switch_name, p4info_parser=None):
        """Convert entries dict to a list of simple_switch_CLI commands."""
        cmds = []
        entries, mc_groups, mirror_sessions, action_profiles = cls._switch_section(
            entries_per_switch, switch_name
        )

        def _params_str(action, params):
            # Action data ordered by p4info param ID when available.
            if p4info_parser and action in p4info_parser._actions:
                ordered = sorted(p4info_parser._actions[action].params,
                                 key=lambda p: p.id)
                parts = [cls._format_value(params[p.name]) for p in ordered]
            else:
                parts = [cls._format_value(v) for v in params.values()]
            return ' '.join(parts)

        # Action profiles / selectors (BMv2 dynamic_action_selection). The SUT
        # entries shape:
        #   "action_profiles": [{
        #     "name": "<act_prof/selector name>",
        #     "members": [{"id": 1, "action_name": "...", "action_params": {...}}, ...],
        #     "groups":  [{"id": 1, "members": [1, 2, 3]}, ...]   # optional (selector)
        #   }]
        # A table entry then references a `member` or `group` id instead of an
        # action (table_indirect_add / table_indirect_add_with_group). BMv2
        # assigns member/group handles sequentially from 0 per profile, in
        # creation order, so we map the SUT's id -> creation index.
        #   act_prof_create_member <prof> <action> <data...>
        #   act_prof_create_group  <prof>
        #   act_prof_add_member_to_group <prof> <mbr_handle> <grp_handle>
        member_handle = {}   # (prof, member_id) -> handle ; also (None, id) global
        group_handle = {}    # (prof, group_id)  -> handle ; also (None, id) global
        for prof in action_profiles:
            pname = prof['name']
            for h, m in enumerate(prof.get('members', [])):
                cmds.append(
                    f"act_prof_create_member {pname} {m['action_name']} "
                    f"{_params_str(m['action_name'], m.get('action_params', {}))}".rstrip()
                )
                member_handle[(pname, m['id'])] = h
                member_handle.setdefault((None, m['id']), h)
            for h, g in enumerate(prof.get('groups', [])):
                cmds.append(f"act_prof_create_group {pname}")
                group_handle[(pname, g['id'])] = h
                group_handle.setdefault((None, g['id']), h)
                for mid in g.get('members', []):
                    cmds.append(
                        f"act_prof_add_member_to_group {pname} "
                        f"{member_handle[(pname, mid)]} {h}"
                    )

        for entry in entries:
            table = entry['table']
            match_str, is_ternary = cls._format_match(entry, p4info_parser)
            prio = f' {int(entry["priority"])}' if is_ternary else ''

            # Indirect (action-profile / selector) entry: references a member or
            # a group id instead of an action_name. `match field` kinds are the
            # same as direct entries (see _format_match): exact / lpm `v/plen` /
            # ternary `v&&&mask` / range `lo->hi`.
            if 'group' in entry:
                prof = entry.get('action_profile')
                h = group_handle[(prof, entry['group'])]
                cmds.append(
                    f'table_indirect_add_with_group {table} {match_str} => {h}{prio}')
                continue
            if 'member' in entry:
                prof = entry.get('action_profile')
                h = member_handle[(prof, entry['member'])]
                cmds.append(f'table_indirect_add {table} {match_str} => {h}{prio}')
                continue

            # Direct entry.
            action = entry['action_name']
            params_str = _params_str(action, entry.get('action_params', {}))
            cmds.append(f'table_add {table} {action} {match_str} => {params_str}{prio}')

        # Multicast groups.  BMv2 simple_switch_CLI supports:
        #   mc_mgrp_create <mgid>
        #   mc_node_create <rid> <port,port,...>
        #   mc_node_associate <mgrp_handle> <node_handle>
        # Node handles are assigned sequentially starting at 0 by BMv2.
        # mgrp_handle == mgid.
        node_handle = 0
        for mg in mc_groups:
            mgid = mg['mgid']
            cmds.append(f'mc_mgrp_create {mgid}')
            nodes = mg.get('nodes')
            if nodes is None:
                # Shorthand: {"mgid": N, "rid": R, "ports": [...]} — one node.
                nodes = [{'rid': mg.get('rid', 0), 'ports': mg['ports']}]
            for node in nodes:
                rid = node.get('rid', 0)
                port_list = ' '.join(str(p) for p in node['ports'])
                cmds.append(f'mc_node_create {rid} {port_list}')
                cmds.append(f'mc_node_associate {mgid} {node_handle}')
                node_handle += 1

        # Mirror sessions. BMv2 simple_switch_CLI command:
        #   mirroring_add <session_id> <egress_port>
        # `egress_port` is the BMv2 integer port number. Each entry is:
        #   {"id": <int session_id>, "egress_port": <int port>}
        for ms in mirror_sessions:
            sid = ms['id']
            port = ms['egress_port']
            cmds.append(f'mirroring_add {sid} {port}')

        return cmds

    @classmethod
    def install(cls, entries_per_switch, switch_name, thrift_port, p4info_parser=None):
        """Install entries via simple_switch_CLI.

        Retries briefly if the switch has not yet finished loading its JSON
        program (Thrift CLI reports 'Invalid table name'); this race appears
        on slower machines where 0.8s startup_wait is not enough.
        """
        cmds = cls.build_cli_commands(entries_per_switch, switch_name, p4info_parser)
        if not cmds:
            return
        cli_input = '\n'.join(cmds) + '\n'

        # Probe the switch first: retry until the expected tables appear in
        # `show_tables` output. This avoids running the real table_add commands
        # while the switch is still loading its JSON (which otherwise fails
        # with 'Invalid table name').
        entries, _, _, _ = cls._switch_section(entries_per_switch, switch_name)
        probe_tables = {entry['table'] for entry in entries}
        for attempt in range(20):
            pr = subprocess.run(
                ['simple_switch_CLI', '--thrift-port', str(thrift_port)],
                input='show_tables\n', capture_output=True, text=True, timeout=10
            )
            # Probe succeeds when the switch answers AND (any expected table is
            # present | we have no table entries to probe by).
            cli_ready = 'RuntimeCmd' in pr.stdout or '>' in pr.stdout
            tables_ok = all(t in pr.stdout for t in probe_tables)
            if cli_ready and tables_ok:
                break
            time.sleep(0.3)

        r = subprocess.run(
            ['simple_switch_CLI', '--thrift-port', str(thrift_port)],
            input=cli_input, capture_output=True, text=True, timeout=15
        )
        errors = [
            line.strip() for line in r.stdout.splitlines()
            if any(kw in line.lower() for kw in ['error', 'cannot', 'invalid', 'fail'])
        ]
        if errors:
            raise RuntimeError(f'Thrift CLI errors: {errors}')
        return r.stdout


class SwitchRunner:
    """
    Run a single BMv2 switch instance using simple_switch --use-files mode.

    Packets are read/written from pcap files in a temp directory:
      {work_dir}/{port}_in.pcap  — input packets for port
      {work_dir}/{port}_out.pcap — output packets from port
    """

    THRIFT_PORT = 9090

    @staticmethod
    def _free_port():
        """Pick an ephemeral free TCP port for this switch's Thrift server.

        Hardcoding 9090 + device-id 0 makes concurrent evaluations on a shared
        host collide (the second switch can't bind the port / its CLI installs
        race), producing false-zero verdicts. A per-instance free port + unique
        device-id isolates every run.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]
        finally:
            s.close()

    def __init__(self, switch_cfg, p4_json_path, thrift_port=None):
        self.name = switch_cfg['name']
        # Unique per-instance device-id so the bmv2 notifications IPC socket
        # (/tmp/bmv2-<device_id>-notifications.ipc) never collides across
        # concurrent evals. device-id has no functional effect on these
        # single-switch v1model tasks.
        self.device_id = switch_cfg.get('device_id') or random.randint(1024, 1_000_000)
        self.ports = switch_cfg['ports']  # {port_name: port_num}
        self.p4_json_path = os.path.abspath(p4_json_path)
        self.thrift_port = thrift_port or self._free_port()
        self.process = None
        self.work_dir = None
        self._start_time = None
        self._all_ports = sorted(self.ports.values())

    def prepare_inputs(self, input_packets):
        """
        Write input pcap files.

        input_packets: dict {port_num: [scapy_pkt, ...]}
        """
        if self.work_dir is None:
            raise RuntimeError('work_dir not set; call setup() first')
        for port in self._all_ports:
            pkts = input_packets.get(port, [])
            out_path = os.path.join(self.work_dir, f'{port}_in.pcap')
            if pkts:
                wrpcap(out_path, pkts)
            else:
                # Write empty pcap
                wrpcap(out_path, [])

    def setup(self, work_dir):
        """Set the working directory for pcap files."""
        self.work_dir = work_dir
        # Create empty output pcap stubs (not required, but avoids confusion)
        for port in self._all_ports:
            wrpcap(os.path.join(work_dir, f'{port}_in.pcap'), [])

    def start(self, startup_wait=1.5):
        """
        Start simple_switch with --use-files.

        The switch reads {port}_in.pcap after USE_FILES_DELAY seconds,
        processes all packets, and writes to {port}_out.pcap.
        """
        cmd = [
            'simple_switch',
            '--use-files', str(USE_FILES_DELAY),
            '--thrift-port', str(self.thrift_port),
            '--device-id', str(self.device_id),
            '-L', 'warn',
        ]
        for port in self._all_ports:
            stem = os.path.join(self.work_dir, str(port))
            cmd += ['-i', f'{port}@{stem}']
        cmd.append(self.p4_json_path)

        self._start_time = time.time()
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=self.work_dir,
        )
        time.sleep(startup_wait)  # wait for Thrift server to come up

    def stop(self, wait_for_output=True):
        """Stop switch and return. Optionally wait for output pcaps."""
        if self.process is None:
            return
        if wait_for_output and self._start_time is not None:
            # The switch processes pcap files at t = _start_time + USE_FILES_DELAY.
            # We just need to wait until that moment has passed (+ a small buffer).
            process_deadline = self._start_time + USE_FILES_DELAY + 0.5
            remaining = process_deadline - time.time()
            if remaining > 0:
                time.sleep(remaining)
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process = None
        self._start_time = None

    def read_output(self, port):
        """Read output packets from a port's pcap file."""
        pcap_path = os.path.join(self.work_dir, f'{port}_out.pcap')
        if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
            return []
        try:
            raw_pkts = rdpcap(pcap_path)
            # simple_switch --use-files writes link-type NULL/Loopback (0);
            # force-parse raw bytes as Ethernet
            return [Ether(bytes(p)) for p in raw_pkts]
        except Exception:
            return []

    def read_all_outputs(self):
        """Return dict {port_num: [Scapy pkt, ...]} for all output ports."""
        return {port: self.read_output(port) for port in self._all_ports}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop()

    @property
    def all_port_nums(self):
        return self._all_ports
