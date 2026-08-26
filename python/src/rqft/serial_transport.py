# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""pyserial byte transport adapter for SyncClient.

This is the only Python module that opens a serial device. Protocol
logic stays in rqft.client and the sans-io layers.
"""

from __future__ import annotations

import importlib
from typing import Any


class SerialTransport:
    """Thin pyserial adapter implementing rqft.client.ByteTransport."""

    def __init__(
        self,
        port: str,
        *,
        baudrate: int = 115200,
        timeout: float = 0.005,
        **kwargs: Any,
    ) -> None:
        """Open a pyserial Serial object.

        Args:
            port: Serial port name, for example ``/dev/ttyACM0`` or
                ``COM4``.
            baudrate: Link baud rate passed to pyserial.
            timeout: Default read timeout in seconds.
            **kwargs: Extra keyword arguments forwarded to
                ``serial.Serial``.

        Raises:
            RuntimeError: If pyserial is not installed.
        """

        try:
            serial_mod = importlib.import_module("serial")
        except ImportError as exc:
            raise RuntimeError("pyserial is required for SerialTransport") from exc
        self._serial: Any = serial_mod.Serial(
            port=port,
            baudrate=baudrate,
            timeout=timeout,
            **kwargs,
        )

    def write(self, data: bytes) -> None:
        """Write all bytes to the serial port."""

        written = self._serial.write(data)
        if written is not None and written != len(data):
            raise OSError("serial write accepted fewer bytes than requested")

    def read(self, max_len: int, timeout: float) -> bytes:
        """Read up to max_len bytes with a per-call timeout."""

        if max_len <= 0:
            raise ValueError("max_len must be positive")
        old_timeout = self._serial.timeout
        self._serial.timeout = timeout
        try:
            return bytes(self._serial.read(max_len))
        finally:
            self._serial.timeout = old_timeout

    def close(self) -> None:
        """Close the serial port."""

        self._serial.close()
