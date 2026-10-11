"""Tests for the MQTT-triggerable ``update`` command that forces an immediate refresh."""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock

import pytest

from carconnectivity.commands import Commands
from carconnectivity.errors import CommandError, SetterError

from carconnectivity_connectors.audi.command_impl import UpdateCommand
from carconnectivity_connectors.audi.connector import UPDATE_COMMAND_COOLDOWN, Connector


def _cmd() -> UpdateCommand:
    return UpdateCommand(parent=Commands(parent=None))


def _connector() -> MagicMock:
    c = MagicMock()
    c._wakeup_event = threading.Event()
    c._last_cycle = time.monotonic() - UPDATE_COMMAND_COOLDOWN - 1
    return c


def _on_update(c: MagicMock, args):
    return Connector._Connector__on_update(c, MagicMock(), args)


@pytest.mark.parametrize("raw", ["start", "update", " START ", ""])
def test_command_parses_strings(raw):
    cmd = _cmd()
    cmd.value = raw
    assert cmd.value["command"] in (UpdateCommand.Command.START, UpdateCommand.Command.UPDATE)


def test_command_rejects_garbage():
    with pytest.raises(SetterError):
        _cmd().value = "bogus"


def test_trigger_wakes_loop():
    c = _connector()
    _on_update(c, {"command": UpdateCommand.Command.START})
    assert c._wakeup_event.is_set()


def test_trigger_within_cooldown_is_ignored():
    c = _connector()
    c._last_cycle = time.monotonic()
    _on_update(c, {"command": UpdateCommand.Command.START})
    assert not c._wakeup_event.is_set()


def test_missing_command_raises():
    with pytest.raises(CommandError):
        _on_update(_connector(), {})


def test_sleep_returns_early_and_resets():
    c = _connector()
    c._wakeup_event.set()
    start = time.monotonic()
    Connector._sleep(c, 30)
    assert time.monotonic() - start < 1
    assert not c._wakeup_event.is_set()
