"""P4Runtime gRPC client for BMv2 simple_switch_grpc."""
import queue
import threading
import time
import math

import grpc
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2
from google.protobuf import text_format

from evaluation.p4info_parser import P4InfoParser


class P4RuntimeClient:
    def __init__(self, grpc_addr, device_id, p4info_path, bmv2_json_path):
        self.grpc_addr = grpc_addr
        self.device_id = device_id
        self.p4info_path = p4info_path
        self.bmv2_json_path = bmv2_json_path

        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)

        self.parser = P4InfoParser(p4info_path)

        self._req_queue = queue.Queue()
        self._resp_queue = queue.Queue()
        self._stop_event = threading.Event()
        self._stream = None
        self._recv_thread = None

    def _req_generator(self):
        while not self._stop_event.is_set():
            try:
                req = self._req_queue.get(timeout=0.2)
                if req is None:
                    return
                yield req
            except queue.Empty:
                continue

    def _recv_loop(self):
        try:
            for resp in self._stream:
                self._resp_queue.put(resp)
        except grpc.RpcError:
            pass

    def connect(self, timeout=10):
        """Open stream, send master arbitration, wait for OK."""
        self._stream = self.stub.StreamChannel(self._req_generator())
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

        req = p4runtime_pb2.StreamMessageRequest()
        req.arbitration.device_id = self.device_id
        req.arbitration.election_id.high = 0
        req.arbitration.election_id.low = 1
        self._req_queue.put(req)

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                resp = self._resp_queue.get(timeout=0.5)
                if resp.HasField('arbitration'):
                    if resp.arbitration.status.code == 0:
                        return  # OK — we are primary controller
                    raise RuntimeError(
                        f"Arbitration failed: code={resp.arbitration.status.code} "
                        f"msg={resp.arbitration.status.message}"
                    )
            except queue.Empty:
                continue
        raise TimeoutError(f"Master arbitration timed out after {timeout}s")

    def set_forwarding_pipeline(self):
        """Load p4info + BMv2 JSON into the switch."""
        p4info = p4info_pb2.P4Info()
        with open(self.p4info_path) as f:
            text_format.Merge(f.read(), p4info)
        with open(self.bmv2_json_path, 'rb') as f:
            device_config = f.read()

        req = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        req.device_id = self.device_id
        req.election_id.high = 0
        req.election_id.low = 1
        req.action = (
            p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        )
        req.config.p4info.CopyFrom(p4info)
        req.config.p4_device_config = device_config
        self.stub.SetForwardingPipelineConfig(req)

    def write_table_entries(self, entries_per_switch, switch_name):
        """Install table entries for one switch from the entries dict."""
        entries = entries_per_switch.get(switch_name, [])
        if not entries:
            return

        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        req.election_id.high = 0
        req.election_id.low = 1

        for e in entries:
            update = req.updates.add()
            update.type = p4runtime_pb2.Update.INSERT
            te = update.entity.table_entry
            te.table_id = self.parser.get_table_id(e['table'])

            # Match fields
            for field_name, raw_value in e.get('match', {}).items():
                mf_proto = self.parser.get_match_field(e['table'], field_name)
                mf = te.match.add()
                mf.field_id = mf_proto.id

                from p4.config.v1.p4info_pb2 import MatchField
                match_type = mf_proto.match_type

                if match_type == MatchField.EXACT:
                    mf.exact.value = self.parser.encode_value(raw_value, mf_proto.bitwidth)
                elif match_type == MatchField.LPM:
                    # raw_value is [ip_str, prefix_len] or just an int
                    if isinstance(raw_value, list):
                        ip_val, prefix_len = raw_value
                    else:
                        ip_val, prefix_len = raw_value, mf_proto.bitwidth
                    mf.lpm.value = self.parser.encode_value(ip_val, mf_proto.bitwidth)
                    mf.lpm.prefix_len = prefix_len
                elif match_type == MatchField.TERNARY:
                    ip_val, mask = raw_value
                    mf.ternary.value = self.parser.encode_value(ip_val, mf_proto.bitwidth)
                    mf.ternary.mask = self.parser.encode_value(mask, mf_proto.bitwidth)

            # Action
            if e.get('default_action'):
                te.is_default_action = True

            action_name = e['action_name']
            te.action.action.action_id = self.parser.get_action_id(action_name)
            for param_name, param_val in e.get('action_params', {}).items():
                param_proto = self.parser.get_action_param(action_name, param_name)
                p = te.action.action.params.add()
                p.param_id = param_proto.id
                p.value = self.parser.encode_value(param_val, param_proto.bitwidth)

            if 'priority' in e:
                te.priority = e['priority']

        self.stub.Write(req)

    def disconnect(self):
        self._stop_event.set()
        self._req_queue.put(None)
        if self._recv_thread:
            self._recv_thread.join(timeout=2)
        self.channel.close()
