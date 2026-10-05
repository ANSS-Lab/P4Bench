"""Scapy layer support for benchmark/relocate/http_header_route_anchor.

P-HTTPHeaderRoute parses a cleartext HTTP/1.1 request line + headers from the
TCP payload. Scapy ships no HTTP-*request* layer the verifier
(evaluation/packet_builder.py) can build from a task.yaml layer spec, and the
shallow-L7 parse this NF performs is over raw payload bytes, not a structured
header with fixed fields. So the HTTP request is carried as raw payload bytes in
the built-in `Raw` layer:

  - INPUT packets (task.yaml `test_cases`): the request bytes are hex-encoded
    under the `load_hex` key of a `Raw` layer spec; packet_builder decodes that
    back to `Raw.load` bytes.
  - EGRESS assertion (http_payload_persistence): the verifier reads `Raw.load`
    with action=unchanged to confirm the request payload is delivered
    byte-for-byte. The verifier's _resolve_layer_cls resolves an unknown layer
    name against THIS module, so we re-export `Raw` here to make `Raw.load`
    resolvable.

No new on-wire header is defined — HTTP/1.1 is a text protocol with no native
Scapy request layer, and the bounded-prefix parse operates on the byte stream
directly (see patterns/P-HTTPHeaderRoute bridging_notes: feasibility). A thin
`HTTPRequest` alias of `Raw` is also exported so callers may name the layer
semantically; both resolve to the same class identity.
"""
from scapy.all import Raw  # noqa: F401  (re-exported for the verifier's layer resolver)

# Semantic alias so a task layer spec / assertion may say HTTPRequest.load if it
# prefers; identical class identity to Raw so build + verify agree.
HTTPRequest = Raw
