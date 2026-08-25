# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Strictness tests for the pure input model — the vocabulary the safety contract
is built on must reject malformed values, since everything downstream trusts it."""

from __future__ import annotations

import pytest

from portal.input.model import (
    InputEvent, InputKind, MouseButton, SessionRef, ViewRef, new_session_nonce,
)

NONCE = new_session_nonce()


def _sess(seq=1):
    return SessionRef(NONCE, seq)


def _view():
    return ViewRef(0, 0)


# -- SessionRef ---------------------------------------------------------------
def test_nonce_must_be_16_bytes():
    with pytest.raises(ValueError):
        SessionRef(b"short", 1)


def test_input_seq_uint64_upper_bound_rejected():
    with pytest.raises(ValueError):
        SessionRef(NONCE, 2**64)  # exactly one past uint64 max


def test_input_seq_max_uint64_accepted():
    SessionRef(NONCE, 2**64 - 1)  # boundary is valid


def test_input_seq_negative_rejected():
    with pytest.raises(ValueError):
        SessionRef(NONCE, -1)


def test_input_seq_bool_rejected():
    # bool is a subclass of int; must not sneak through.
    with pytest.raises(ValueError):
        SessionRef(NONCE, True)


# -- ViewRef ------------------------------------------------------------------
def test_view_epoch_negative_rejected():
    with pytest.raises(ValueError):
        ViewRef(-1, 0)


def test_frame_seq_negative_rejected():
    with pytest.raises(ValueError):
        ViewRef(0, -5)


# -- InputEvent shape ---------------------------------------------------------
def test_move_requires_nonempty_display_id():
    ev = InputEvent(kind=InputKind.MOVE, display_id="", x=0.5, y=0.5,
                    session=_sess(), view=_view())
    with pytest.raises(ValueError):
        ev.validate_shape()


def test_move_coords_out_of_range_rejected():
    for x, y in [(-0.01, 0.5), (0.5, 1.01), (2.0, 0.0)]:
        ev = InputEvent(kind=InputKind.MOVE, display_id="d", x=x, y=y,
                        session=_sess(), view=_view())
        with pytest.raises(ValueError):
            ev.validate_shape()


def test_move_nan_inf_rejected():
    for bad in [float("nan"), float("inf"), float("-inf")]:
        ev = InputEvent(kind=InputKind.MOVE, display_id="d", x=bad, y=0.5,
                        session=_sess(), view=_view())
        with pytest.raises(ValueError):
            ev.validate_shape()


def test_button_pressed_must_be_bool():
    ev = InputEvent(kind=InputKind.BUTTON, button=MouseButton.LEFT, pressed="yes",
                    session=_sess(), view=_view())
    with pytest.raises(ValueError):
        ev.validate_shape()


def test_wheel_delta_must_be_int():
    ev = InputEvent(kind=InputKind.WHEEL, wheel_delta=1.5, session=_sess(), view=_view())
    with pytest.raises(ValueError):
        ev.validate_shape()


def test_valid_events_pass():
    InputEvent(kind=InputKind.MOVE, display_id="d", x=0.0, y=1.0,
               session=_sess(), view=_view()).validate_shape()
    InputEvent(kind=InputKind.BUTTON, button=MouseButton.LEFT, pressed=True,
               session=_sess(), view=_view()).validate_shape()
    InputEvent(kind=InputKind.WHEEL, wheel_delta=-3, session=_sess(), view=_view()).validate_shape()


def test_owned_release_detection():
    up = InputEvent(kind=InputKind.BUTTON, button=MouseButton.LEFT, pressed=False,
                    session=_sess(), view=_view())
    down = InputEvent(kind=InputKind.BUTTON, button=MouseButton.LEFT, pressed=True,
                      session=_sess(), view=_view())
    assert up.is_owned_release()
    assert not down.is_owned_release()
