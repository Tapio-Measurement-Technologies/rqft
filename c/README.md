# librqft

C++17 implementation of RQFT with C99-compatible public headers.

Library uses no heap allocation or globals. Callers own all contexts and
provide transport, event, clock, and filesystem integration.

## PlatformIO

Install a tagged GitHub release archive:

```ini
[env:device]
lib_deps =
    rqft=https://github.com/Tapio-Measurement-Technologies/rqft/releases/download/v1.0.0/rqft-platformio-1.0.0.tar.gz
```

`library.json` applies C++17 mode to library sources.

For local development against a repository checkout:

```ini
[env:device]
lib_deps =
    rqft=symlink://../rqft/c
```

Include complete public API:

```cpp
#include <rqft/rqft.h>
```

## CMake

Build and install standalone library:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DRQFT_BUILD_TESTS=OFF -DRQFT_BUILD_INTEROP=OFF
cmake --build build
cmake --install build --prefix /desired/prefix
```

Installed package exports `rqft::rqft`:

```cmake
find_package(rqft CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE rqft::rqft)
```

Repository checkout enables native tests and interoperability peer by default.
Sanitizers remain opt-in through `-DRQFT_SANITIZE=ON`.

## Versioning

Release version comes from exact Git tag `vMAJOR.MINOR.PATCH`. Tagged CMake
checkouts derive it directly. Published PlatformIO/CMake archives carry a
generated `VERSION` file and matching `library.json` metadata, so they build
without Git history. Tag CI publishes the archive as a GitHub Release asset
after package, implementation, interoperability, and fuzz tests pass.

## License

Copyright © 2026
[Tapio Measurement Technologies Oy](https://tapiotechnologies.com).

Licensed under GNU General Public License v3.0 only. See `LICENSE`. The copyright owner may use and license its own code separately.
