# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Golden session trace replay tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

from fakefs import FakeFs
from rqft.events import Ended, GetDone, GetServed, ListDone, NotifyReceived
from rqft.events import PutDone as PutDoneEvent
from rqft.link import AbortReason
from rqft.messages import NOTIFY_SYNC_INCREMENTAL, Role
from rqft.session import Session

ROOT = Path(__file__).resolve().parents[2]
SID = 0x42


@dataclass(frozen=True)
class TraceEntry:
    """One timestamped wire chunk from a session trace file."""

    now_ms: int
    direction: str
    hex_data: str


def load_trace(name: str) -> list[TraceEntry]:
    """Load one line-oriented session trace."""

    entries: list[TraceEntry] = []
    path = ROOT / "testvectors" / "sessions" / f"{name}.trace"
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        now_text, direction, hex_data = line.split()
        entries.append(TraceEntry(int(now_text), direction, hex_data))
    return entries


class Capture:
    """Collect exact endpoint output chunks for comparison to a trace."""

    def __init__(self) -> None:
        """Initialize an empty capture log."""

        self.entries: list[TraceEntry] = []

    def record(self, now_ms: int, direction: str, data: bytes) -> None:
        """Append non-empty emitted wire bytes."""

        if data:
            self.entries.append(TraceEntry(now_ms, direction, data.hex()))


def pair(
    ctrl_fs: FakeFs | None = None,
    resp_fs: FakeFs | None = None,
    *,
    sid: int = SID,
    resp_ver_min: int = 1,
    resp_ver_max: int = 1,
) -> tuple[Session, Session]:
    """Create a deterministic controller/responder session pair."""

    ctrl = Session(Role.CONTROLLER, sid_source=lambda: sid, fs=ctrl_fs)
    resp = Session(
        Role.RESPONDER,
        sid_source=lambda: sid,
        fs=resp_fs,
        ver_min=resp_ver_min,
        ver_max=resp_ver_max,
    )
    return ctrl, resp


def shuttle(
    ctrl: Session, resp: Session, capture: Capture, now_ms: int
) -> tuple[list[object], list[object]]:
    """Move queued bytes and pending work until both endpoints go quiet."""

    ctrl_events: list[object] = []
    resp_events: list[object] = []
    for _ in range(400):
        progressed = False

        outbound = ctrl.data_to_send()
        if outbound:
            capture.record(now_ms, "C>R", outbound)
            resp_events += resp.receive_bytes(outbound, now_ms)
            progressed = True

        if resp.work_pending():
            resp_events += resp.handle_timeout(now_ms)
            progressed = True

        inbound = resp.data_to_send()
        if inbound:
            capture.record(now_ms, "R>C", inbound)
            ctrl_events += ctrl.receive_bytes(inbound, now_ms)
            progressed = True

        if ctrl.work_pending():
            ctrl_events += ctrl.handle_timeout(now_ms)
            progressed = True

        if not progressed:
            return ctrl_events, resp_events

    raise AssertionError("endpoints never went quiet")


def capture_hello_list_get() -> list[TraceEntry]:
    """Capture controller startup, LIST with CRCs, and one GET."""

    capture = Capture()
    ctrl_fs = FakeFs()
    resp_fs = FakeFs(
        {"a.data": b"alpha", "logs/run1.data": b"first run"},
        mtimes={"a.data": 1735689600},
    )
    ctrl, resp = pair(ctrl_fs, resp_fs)

    ctrl.start(now_ms=0)
    shuttle(ctrl, resp, capture, now_ms=0)

    ctrl.request_list("", want_crc=True, now_ms=10)
    ctrl_events, _ = shuttle(ctrl, resp, capture, now_ms=10)
    assert isinstance(ctrl_events[-1], ListDone)

    ctrl.request_get("a.data", now_ms=20)
    ctrl_events, resp_events = shuttle(ctrl, resp, capture, now_ms=20)
    assert ctrl_events[-1] == GetDone("a.data", 5, 0xD0E0396A)
    assert resp_events[-1] == GetServed("a.data", 5, 0xD0E0396A)
    assert ctrl_fs.files["a.data"] == b"alpha"
    return capture.entries


def capture_put() -> list[TraceEntry]:
    """Capture controller startup and one PUT."""

    capture = Capture()
    ctrl_fs = FakeFs({"upload.bin": b"bravo-data"})
    resp_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, resp_fs)

    ctrl.start(now_ms=0)
    shuttle(ctrl, resp, capture, now_ms=0)

    ctrl.request_put("upload.bin", now_ms=10)
    ctrl_events, _ = shuttle(ctrl, resp, capture, now_ms=10)
    assert ctrl_events[-1] == PutDoneEvent("upload.bin", 10, 0x37706819)
    assert resp_fs.files["upload.bin"] == b"bravo-data"
    return capture.entries


def capture_abort() -> list[TraceEntry]:
    """Capture a version-negotiation abort."""

    capture = Capture()
    ctrl, resp = pair(resp_ver_min=2, resp_ver_max=2)

    ctrl.start(now_ms=0)
    ctrl_events, _ = shuttle(ctrl, resp, capture, now_ms=0)
    assert ctrl_events == [Ended(AbortReason.E_VERSION, from_peer=True)]
    return capture.entries


def capture_user_abort() -> list[TraceEntry]:
    """Capture a responder-side user cancel of an active session."""

    capture = Capture()
    ctrl, resp = pair()

    ctrl.start(now_ms=0)
    shuttle(ctrl, resp, capture, now_ms=0)
    assert ctrl.session_active and resp.session_active

    resp_events = resp.abort(AbortReason.E_USER, now_ms=10)
    assert resp_events == [Ended(AbortReason.E_USER, from_peer=False)]
    outbound = resp.data_to_send()
    capture.record(10, "R>C", outbound)
    ctrl_events = ctrl.receive_bytes(outbound, now_ms=10)
    assert ctrl_events == [Ended(AbortReason.E_USER, from_peer=True)]
    return capture.entries


def capture_doorbell() -> list[TraceEntry]:
    """Capture responder-role HELLO doorbell startup."""

    capture = Capture()
    device = Session(Role.RESPONDER, sid_source=lambda: 0x51, caps=1)
    host = Session(Role.CONTROLLER)

    device.start(now_ms=0)
    outbound = device.data_to_send()
    capture.record(0, "R>C", outbound)
    host.receive_bytes(outbound, now_ms=5)

    inbound = host.data_to_send()
    capture.record(10, "C>R", inbound)
    device.receive_bytes(inbound, now_ms=10)

    assert host.session_active and device.session_active
    return capture.entries


def capture_doorbell_notify() -> list[TraceEntry]:
    """Capture a doorbell establish followed by NOTIFY(SYNC_INCREMENTAL)."""

    capture = Capture()
    device = Session(Role.RESPONDER, sid_source=lambda: 0x51, caps=1)
    host = Session(Role.CONTROLLER)

    device.start(now_ms=0)
    outbound = device.data_to_send()
    capture.record(0, "R>C", outbound)
    host.receive_bytes(outbound, now_ms=5)

    inbound = host.data_to_send()
    capture.record(10, "C>R", inbound)
    device.receive_bytes(inbound, now_ms=10)
    assert host.session_active and device.session_active

    device.send_notify(NOTIFY_SYNC_INCREMENTAL, now_ms=20)
    outbound = device.data_to_send()
    capture.record(20, "R>C", outbound)
    host_events = host.receive_bytes(outbound, now_ms=20)
    assert NotifyReceived(NOTIFY_SYNC_INCREMENTAL) in host_events

    # Let the device absorb the link-level ACK so both sides go quiet.
    inbound = host.data_to_send()
    if inbound:
        capture.record(20, "C>R", inbound)
        device.receive_bytes(inbound, now_ms=20)
    return capture.entries


@pytest.mark.parametrize(
    ("name", "capture_fn"),
    [
        ("hello_list_get", capture_hello_list_get),
        ("put", capture_put),
        ("abort", capture_abort),
        ("user_abort", capture_user_abort),
        ("doorbell", capture_doorbell),
        ("doorbell_notify", capture_doorbell_notify),
    ],
)
def test_session_trace_matches_golden(
    name: str, capture_fn: Callable[[], list[TraceEntry]]
) -> None:
    """Replay one canonical scenario and compare exact wire bytes."""

    assert capture_fn() == load_trace(name)
