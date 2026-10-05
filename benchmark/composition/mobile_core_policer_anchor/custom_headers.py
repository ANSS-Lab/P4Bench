"""Expose the Scapy contrib GTP-U layer to the evaluation packet builder.

This task sends GTP-U-encapsulated uplink packets as test INPUT (the SUT must
decapsulate them). `evaluation/packet_builder._build_layer` resolves an unknown
layer name against this module first, then falls back to `scapy.layers.all` —
which does NOT contain contrib layers such as GTP_U_Header. Without this
re-export the input packet cannot be built. `evaluation/verifier._resolve_layer_cls`
already imports the same class for output-field checking, so this keeps build
and verify on one class identity.
"""
from scapy.contrib.gtp import GTP_U_Header  # noqa: F401
