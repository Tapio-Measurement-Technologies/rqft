# rqft

Typed Python implementation of RQFT, a robust file-transfer protocol for
unreliable byte streams.

Requires Python 3.12 or newer.

Package provides:

- pure sans-I/O frame, link, and session layers;
- blocking `SyncClient` and generic `BlockingSessionDriver`;
- optional pyserial transport;
- typed events, filesystem interfaces, diagnostics, and progress snapshots;
- interactive `rqft-demo` client with an in-process loopback responder.

## Install

Install core library from a tagged GitHub release:

```sh
python -m pip install "rqft @ https://github.com/Tapio-Measurement-Technologies/rqft/releases/download/v1.0.0/rqft-1.0.0-py3-none-any.whl"
```

Install pyserial adapter:

```sh
python -m pip install "rqft[serial] @ https://github.com/Tapio-Measurement-Technologies/rqft/releases/download/v1.0.0/rqft-1.0.0-py3-none-any.whl"
```

Use the same direct reference in another project's `pyproject.toml`:

```toml
[project]
dependencies = [
    "rqft[serial] @ https://github.com/Tapio-Measurement-Technologies/rqft/releases/download/v1.0.0/rqft-1.0.0-py3-none-any.whl",
]
```

Each GitHub Release also provides the source distribution and `SHA256SUMS`.

## Minimal serial client

```python
from pathlib import Path

from rqft.client import SyncClient
from rqft.serial_transport import SerialTransport

transport = SerialTransport("/dev/ttyACM0", baudrate=115200)
client = SyncClient(transport, Path("downloads"))
try:
    result = client.sync_from_peer(delete_remote=False)
    print(result)
finally:
    client.close()
```

Protocol specification, C implementation, shared vectors, and interoperability
tests live in the
[rqft repository](https://github.com/Tapio-Measurement-Technologies/rqft).

## License

Copyright © 2026
[Tapio Measurement Technologies Oy](https://tapiotechnologies.com).

Licensed under GNU General Public License v3.0 only. See `LICENSE`. The copyright owner may use and license its own code separately.
