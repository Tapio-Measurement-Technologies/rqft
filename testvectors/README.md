# Golden test vectors

Shared, human-readable fixtures consumed byte-exact by **both** the C and
Python test suites. They pin the wire format: changing any file here is a
protocol change and must be reflected in SPEC.md.

| File | Format |
|---|---|
| `crc32.json` | `[{"input_hex": "...", "crc32": <u32>}, ...]` |
| `cobs.json` | `[{"decoded_hex": "...", "encoded_hex": "..."}, ...]` |
| `frames.json` | `[{"name": "...", "ftype": .., "sid": .., "seq": .., "flags": .., "payload_hex": "...", "encoded_hex": "..."}, ...]` |
| `rto.json` | `[{"case": "...", "step": .., "rtt": .., "srtt": .., "rttvar": .., "rto": ..}, ...]` — one estimator run per `case`, expected state after each sample |
| `messages.json` | `[{"kind": "...", "name": "...", <fields per kind>, "encoded_hex": "..."}, ...]` — session body/message codecs, one object per line |
| `sessions/*.trace` | byte-exact session transcripts using format defined below |

Binary data is lowercase hex in JSON strings so diffs stay reviewable.

## Session trace format

Session traces are line-oriented UTF-8 text:

```text
# rqft-session-trace-v1
# name: hello_list_get
# scenario: short human description
# columns: now_ms direction hex
0 C>R 00...
10 R>C 00...
```

Blank lines and `#` comments are ignored. Data lines contain a monotonic
timestamp in milliseconds, a direction (`C>R` from controller to responder
or `R>C` from responder to controller), and one lowercase hex blob with the
exact bytes emitted by that endpoint before the peer receives them.
