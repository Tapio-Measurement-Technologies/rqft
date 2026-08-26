# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Session handshake tests for SPEC.md sections 4.2, 5.1, and 5.2."""

from __future__ import annotations

from typing import TypedDict, Unpack

import pytest

from rqft.events import Ended, Established, NotifyReceived, SessionEvent
from rqft.frame import Frame, FrameType, Parser, Passthrough, build_frame
from rqft.link import AbortReason
from rqft.messages import NOTIFY_SYNC_INCREMENTAL, Hello, HelloOk, Role
from rqft.rto import RTO_INITIAL_MS
from rqft.session import (
    N_HELLO,
    Session,
    SessionDiagnostics,
    SessionError,
    SessionState,
    T_HELLO_MS,
)


class _SessionKwargs(TypedDict, total=False):
    """Integer-valued Session keyword arguments forwarded by make_session."""

    ver_min: int
    ver_max: int
    max_payload: int
    window: int
    caps: int


def make_session(role: Role, sid: int = 0x42, **kwargs: Unpack[_SessionKwargs]) -> Session:
    return Session(role, sid_source=lambda: sid, **kwargs)


def frames(data: bytes) -> list[Frame]:
    parsed = Parser().feed(data, now_ms=0)
    assert all(isinstance(event, Frame) for event in parsed)
    return [event for event in parsed if isinstance(event, Frame)]


def hello_wire(
    sid: int,
    role: Role = Role.CONTROLLER,
    ver_min: int = 1,
    ver_max: int = 1,
    max_payload: int = 512,
    window: int = 4,
    caps: int = 0,
) -> bytes:
    body = Hello(ver_min, ver_max, role, max_payload, window, caps).encode()
    return build_frame(FrameType.HELLO, sid, 0, 0, body)


def hello_ok_wire(
    sid: int,
    role: Role = Role.RESPONDER,
    ver: int = 1,
    max_payload: int = 512,
    window: int = 4,
    caps: int = 0,
) -> bytes:
    body = HelloOk(ver, role, max_payload, window, caps).encode()
    return build_frame(FrameType.HELLO_OK, sid, 0, 0, body)


def abort_wire(sid: int, reason: AbortReason) -> bytes:
    return build_frame(FrameType.ABORT, sid, 0, 0, bytes([reason]))


def test_config_validation() -> None:
    with pytest.raises(SessionError):
        Session(Role.CONTROLLER, ver_min=2, ver_max=1)
    with pytest.raises(SessionError):
        Session(Role.CONTROLLER, max_payload=0)
    with pytest.raises(SessionError):
        Session(Role.CONTROLLER, max_payload=513)
    with pytest.raises(SessionError):
        Session(Role.CONTROLLER, window=0)
    with pytest.raises(SessionError):
        Session(Role.CONTROLLER, window=9)

    bad_sid = Session(Role.CONTROLLER, sid_source=lambda: 0)
    with pytest.raises(SessionError):
        bad_sid.start(now_ms=0)


def test_initiator_happy_path_negotiates_minimums() -> None:
    session = make_session(Role.CONTROLLER, max_payload=512, window=4, caps=0)
    session.start(now_ms=0)

    sent = frames(session.data_to_send())
    assert len(sent) == 1
    assert sent[0].type is FrameType.HELLO
    assert sent[0].sid == 0x42
    hello = Hello.decode(sent[0].payload)
    assert hello == Hello(1, 1, Role.CONTROLLER, 512, 4, 0)

    events = session.receive_bytes(
        hello_ok_wire(0x42, max_payload=256, window=2, caps=1), now_ms=200
    )
    assert events == [Established(0x42, 1, Role.CONTROLLER, 256, 2, 1)]
    assert session.state is SessionState.ACTIVE
    assert session.session_active


def test_diagnostics_snapshots_frame_and_link_state() -> None:
    """Session exposes immutable parser and active-link diagnostics."""

    session = make_session(Role.CONTROLLER)
    assert session.diagnostics() == SessionDiagnostics(
        frames_ok=0,
        frames_crc_fail=0,
        frames_oversize=0,
        frames_dropped=0,
        candidates_idle_flushed=0,
        valid_candidates_idle_flushed=0,
        bytes_idle_flushed=0,
        frames_wrong_sid=0,
        frames_retransmitted=0,
        naks_sent=0,
        duplicate_data_received=0,
        out_of_order_data_received=0,
        bytes_passthrough=0,
        bytes_dropped_in_session=0,
        srtt_ms=None,
        rttvar_ms=None,
        rto_ms=None,
        in_flight=None,
    )

    session.start(now_ms=0)
    session.receive_bytes(hello_ok_wire(0x42), now_ms=200)
    before_noise = session.diagnostics()
    wrong_sid_ack = build_frame(FrameType.ACK, 0x99, 0, 0, b"")
    session.receive_bytes(b"noise" + wrong_sid_ack, now_ms=201)

    assert before_noise.frames_crc_fail == 0
    assert session.diagnostics() == SessionDiagnostics(
        frames_ok=2,
        frames_crc_fail=1,
        frames_oversize=0,
        frames_dropped=0,
        candidates_idle_flushed=0,
        valid_candidates_idle_flushed=0,
        bytes_idle_flushed=0,
        frames_wrong_sid=1,
        frames_retransmitted=0,
        naks_sent=0,
        duplicate_data_received=0,
        out_of_order_data_received=0,
        bytes_passthrough=0,
        bytes_dropped_in_session=5,
        # The handshake round trip seeds nothing (SPEC 4.4): the active
        # link starts with an untrained estimator at RTO_INITIAL_MS.
        srtt_ms=None,
        rttvar_ms=None,
        rto_ms=1000,
        in_flight=0,
    )


def test_start_twice_raises() -> None:
    session = make_session(Role.CONTROLLER)
    session.start(now_ms=0)
    with pytest.raises(SessionError):
        session.start(now_ms=1)


def test_replier_happy_path_answers_hello_ok() -> None:
    session = make_session(Role.RESPONDER, max_payload=512, window=4, caps=1)

    events = session.receive_bytes(hello_wire(0x37, max_payload=128, window=8), now_ms=10)

    assert events == [Established(0x37, 1, Role.RESPONDER, 128, 4, 0)]
    assert session.state is SessionState.ACTIVE
    sent = frames(session.data_to_send())
    assert len(sent) == 1
    assert sent[0].type is FrameType.HELLO_OK
    assert sent[0].sid == 0x37
    assert HelloOk.decode(sent[0].payload) == HelloOk(1, Role.RESPONDER, 512, 4, 1)


def test_doorbell_roles_and_steady_state() -> None:
    device = make_session(Role.RESPONDER, sid=0x51, caps=1)
    host = Session(Role.CONTROLLER)

    device.start(now_ms=0)
    host_events = host.receive_bytes(device.data_to_send(), now_ms=5)
    device_events = device.receive_bytes(host.data_to_send(), now_ms=10)

    assert host_events == [Established(0x51, 1, Role.CONTROLLER, 512, 4, 1)]
    assert device_events == [Established(0x51, 1, Role.RESPONDER, 512, 4, 0)]
    assert host.session_active and device.session_active


def test_doorbell_then_notify() -> None:
    device = make_session(Role.RESPONDER, sid=0x51, caps=1)
    host = Session(Role.CONTROLLER)

    device.start(now_ms=0)
    host.receive_bytes(device.data_to_send(), now_ms=5)
    device.receive_bytes(host.data_to_send(), now_ms=10)
    assert host.session_active and device.session_active

    # The established responder asks for an incremental pull mid-session.
    device.send_notify(NOTIFY_SYNC_INCREMENTAL, now_ms=20)
    host_events = host.receive_bytes(device.data_to_send(), now_ms=20)

    assert NotifyReceived(NOTIFY_SYNC_INCREMENTAL) in host_events
    assert host.session_active and device.session_active


def test_send_notify_rejects_misuse() -> None:
    device = make_session(Role.RESPONDER, sid=0x51, caps=1)
    host = Session(Role.CONTROLLER)

    # Not active yet.
    with pytest.raises(SessionError):
        device.send_notify(0, now_ms=0)

    device.start(now_ms=0)
    host.receive_bytes(device.data_to_send(), now_ms=5)
    device.receive_bytes(host.data_to_send(), now_ms=10)
    assert device.session_active

    # Controllers do not send NOTIFY.
    with pytest.raises(SessionError):
        host.send_notify(0, now_ms=20)

    # Senders must zero undefined NOTIFY flag bits.
    with pytest.raises(SessionError):
        device.send_notify(0x04, now_ms=20)
    with pytest.raises(SessionError):
        device.send_notify(1 << 31, now_ms=20)


def test_version_negotiation_picks_highest_common() -> None:
    session = Session(Role.RESPONDER, ver_min=2, ver_max=5)

    events = session.receive_bytes(hello_wire(0x37, ver_min=1, ver_max=3), now_ms=0)

    assert isinstance(events[0], Established)
    assert events[0].version == 3
    sent = frames(session.data_to_send())
    assert HelloOk.decode(sent[0].payload).ver == 3


def test_version_no_overlap_aborts_and_stays_idle() -> None:
    session = Session(Role.RESPONDER, ver_min=2, ver_max=3)

    events = session.receive_bytes(hello_wire(0x37, ver_min=1, ver_max=1), now_ms=0)

    assert events == []
    assert session.state is SessionState.IDLE
    sent = frames(session.data_to_send())
    assert [(f.type, f.sid, f.payload) for f in sent] == [
        (FrameType.ABORT, 0x37, bytes([AbortReason.E_VERSION]))
    ]

    # The endpoint still accepts a compatible HELLO afterwards.
    events = session.receive_bytes(hello_wire(0x38, ver_min=2, ver_max=2), now_ms=10)
    assert isinstance(events[0], Established)


def test_initiator_rejects_version_outside_range() -> None:
    session = make_session(Role.CONTROLLER)
    session.start(now_ms=0)
    session.data_to_send()

    events = session.receive_bytes(hello_ok_wire(0x42, ver=7), now_ms=10)

    assert events == [Ended(AbortReason.E_VERSION, from_peer=False)]
    assert session.state is SessionState.ENDED
    sent = frames(session.data_to_send())
    assert [(f.type, f.payload) for f in sent] == [
        (FrameType.ABORT, bytes([AbortReason.E_VERSION]))
    ]


def test_same_role_hello_rejected_with_e_proto() -> None:
    session = Session(Role.RESPONDER)

    events = session.receive_bytes(hello_wire(0x37, role=Role.RESPONDER), now_ms=0)

    assert events == []
    assert session.state is SessionState.IDLE
    sent = frames(session.data_to_send())
    assert [(f.type, f.sid, f.payload) for f in sent] == [
        (FrameType.ABORT, 0x37, bytes([AbortReason.E_PROTO]))
    ]


def test_initiator_rejects_same_role_hello_ok() -> None:
    session = make_session(Role.CONTROLLER)
    session.start(now_ms=0)

    events = session.receive_bytes(hello_ok_wire(0x42, role=Role.CONTROLLER), now_ms=10)

    assert events == [Ended(AbortReason.E_PROTO, from_peer=False)]
    assert session.state is SessionState.ENDED


def test_initiator_abort_reply_ends_handshake() -> None:
    session = make_session(Role.CONTROLLER)
    session.start(now_ms=0)

    events = session.receive_bytes(abort_wire(0x42, AbortReason.E_BUSY), now_ms=10)

    assert events == [Ended(AbortReason.E_BUSY, from_peer=True)]
    assert session.state is SessionState.ENDED


def test_handshake_ignores_foreign_sid_replies() -> None:
    session = make_session(Role.CONTROLLER)
    session.start(now_ms=0)

    assert session.receive_bytes(hello_ok_wire(0x99), now_ms=10) == []
    assert session.receive_bytes(abort_wire(0x99, AbortReason.E_BUSY), now_ms=11) == []
    assert session.state is SessionState.HELLO_SENT


def test_hello_retry_schedule_and_giveup() -> None:
    session = make_session(Role.CONTROLLER)
    session.start(now_ms=0)
    assert session.next_timeout() == T_HELLO_MS

    hello_count = 1
    events: list[SessionEvent] = []
    now = 0
    while not events and now < 10_000:
        now += T_HELLO_MS
        assert session.handle_timeout(now - 1) == []
        events = session.handle_timeout(now)
        hello_count += 1 if not events else 0

    assert events == [Ended(AbortReason.E_TIMEOUT, from_peer=False)]
    assert session.state is SessionState.ENDED
    assert hello_count == N_HELLO
    assert now == N_HELLO * T_HELLO_MS
    sent = frames(session.data_to_send())
    assert len(sent) == N_HELLO
    assert all(f.type is FrameType.HELLO and f.sid == 0x42 for f in sent)
    # No ABORT frame accompanies a handshake timeout; the failure is local.


def test_hello_rtt_does_not_seed_link_estimator() -> None:
    # The unloaded handshake round trip undershoots loaded RTT (SPEC 4.4);
    # the link starts at RTO_INITIAL_MS with an untrained estimator.
    session = make_session(Role.CONTROLLER)
    session.start(now_ms=0)

    session.receive_bytes(hello_ok_wire(0x42), now_ms=200)

    link = session._link
    assert link is not None
    assert link._estimator.srtt_ms == -1
    assert link._rto_ms == RTO_INITIAL_MS


def test_idempotent_hello_ok_resend() -> None:
    session = make_session(Role.RESPONDER)
    session.receive_bytes(hello_wire(0x37), now_ms=0)
    first = session.data_to_send()

    events = session.receive_bytes(hello_wire(0x37), now_ms=600)

    assert events == []
    assert session.data_to_send() == first
    assert session.state is SessionState.ACTIVE


def test_busy_endpoint_aborts_new_sid_only() -> None:
    session = make_session(Role.RESPONDER)
    session.receive_bytes(hello_wire(0x37), now_ms=0)
    session.data_to_send()

    events = session.receive_bytes(hello_wire(0x99), now_ms=10)

    assert events == []
    assert session.state is SessionState.ACTIVE
    sent = frames(session.data_to_send())
    assert [(f.type, f.sid, f.payload) for f in sent] == [
        (FrameType.ABORT, 0x99, bytes([AbortReason.E_BUSY]))
    ]


def test_collision_lower_sid_wins() -> None:
    low = make_session(Role.CONTROLLER, sid=0x10)
    high = make_session(Role.RESPONDER, sid=0x20)
    low.start(now_ms=0)
    high.start(now_ms=0)
    low_hello = low.data_to_send()
    high_hello = high.data_to_send()

    # The higher-sid endpoint abandons its own HELLO and answers.
    high_events = high.receive_bytes(low_hello, now_ms=10)
    assert high_events == [Established(0x10, 1, Role.RESPONDER, 512, 4, 0)]

    # The lower-sid endpoint ignores the crossing HELLO and wins.
    assert low.receive_bytes(high_hello, now_ms=11) == []
    assert low.state is SessionState.HELLO_SENT
    low_events = low.receive_bytes(high.data_to_send(), now_ms=12)
    assert low_events == [Established(0x10, 1, Role.CONTROLLER, 512, 4, 0)]


def test_collision_equal_sids_rerandomize_after_t_hello() -> None:
    a_sids = iter([0x42, 0x11])
    b_sids = iter([0x42, 0x33])
    a = Session(Role.CONTROLLER, sid_source=lambda: next(a_sids))
    b = Session(Role.RESPONDER, sid_source=lambda: next(b_sids))
    a.start(now_ms=0)
    b.start(now_ms=0)
    a_hello = a.data_to_send()
    b_hello = b.data_to_send()

    # Both abandon silently and stay quiet until T_HELLO passes.
    assert a.receive_bytes(b_hello, now_ms=10) == []
    assert b.receive_bytes(a_hello, now_ms=10) == []
    assert a.data_to_send() == b"" and b.data_to_send() == b""
    assert a.next_timeout() == 10 + T_HELLO_MS

    assert a.handle_timeout(10 + T_HELLO_MS) == []
    assert b.handle_timeout(10 + T_HELLO_MS) == []
    a_wire = a.data_to_send()
    b_wire = b.data_to_send()
    assert [f.sid for f in frames(a_wire)] == [0x11]
    assert [f.sid for f in frames(b_wire)] == [0x33]

    # The re-randomized handshake completes; 0x11 < 0x33 wins.
    b_events = b.receive_bytes(a_wire, now_ms=520)
    assert b_events == [Established(0x11, 1, Role.RESPONDER, 512, 4, 0)]
    a_events = a.receive_bytes(b.data_to_send(), now_ms=530)
    assert a_events == [Established(0x11, 1, Role.CONTROLLER, 512, 4, 0)]


def test_passthrough_inactive_and_dropped_when_active() -> None:
    session = make_session(Role.RESPONDER)
    text = b"STATUS?\r\n"

    events = session.receive_bytes(text, now_ms=0)
    assert all(isinstance(event, Passthrough) for event in events)
    assert b"".join(e.data for e in events if isinstance(e, Passthrough)) == text

    session.receive_bytes(hello_wire(0x37), now_ms=10)
    assert session.receive_bytes(b"stray console noise", now_ms=20) == []


def test_malformed_hello_body_dropped_silently() -> None:
    session = Session(Role.RESPONDER)
    body = bytearray(Hello(1, 1, Role.CONTROLLER, 512, 4, 0).encode())
    body[2] = 7  # undefined role byte

    events = session.receive_bytes(
        build_frame(FrameType.HELLO, 0x37, 0, 0, bytes(body)), now_ms=0
    )

    assert events == []
    assert session.state is SessionState.IDLE
    assert session.data_to_send() == b""


def test_next_timeout_idle_is_none() -> None:
    session = make_session(Role.RESPONDER)
    assert session.next_timeout() is None
