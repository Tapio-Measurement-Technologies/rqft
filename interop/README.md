# Interop + fault-injection harness

Proves the C and Python implementations interoperate under hostile line
conditions. This matrix is the project's robustness proof.

Current contents:

- `c_peer/main.cpp` — the C++17 library compiled natively into a stdio/TCP
  peer with an in-memory filesystem (role, served files, and seed set via
  CLI).
- `fault_shim.py` — deterministic seeded duplex fault injector: byte drop,
  duplication, corruption, burst drops, re-chunking (down to 1-byte
  deliveries), latency jitter, ASCII chatter injection.
- `harness.py` / pytest suites — subprocess pump tests for clean-line
  LIST, GET, and PUT in both C↔Python role assignments, plus the full fault
  matrix.

Run: `pytest interop` from the repo root.
