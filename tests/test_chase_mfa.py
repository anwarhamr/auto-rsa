from __future__ import annotations

import io
import unittest
from unittest import mock

from src.brokerages import chase_mfa
from src.brokerages.chase_mfa import (
    ChaseMFACancelledError,
    ChaseMFAError,
    ChaseMFATimedOutError,
    collect_chase_mfa_code,
)


class _Terminal:
    def __enter__(self) -> _Terminal:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class ChaseMFAInputTests(unittest.TestCase):
    def test_invalid_input_is_retried_and_success_is_not_echoed(self) -> None:
        output = io.StringIO()
        with mock.patch.object(chase_mfa, "_read_masked_line", side_effect=["1234", "87654321"]):
            result = collect_chase_mfa_code(
                timeout=30,
                terminal_factory=_Terminal,  # type: ignore[arg-type]
                output=output,
            )
        self.assertEqual(result, "87654321")
        self.assertIn("exactly 8 digits", output.getvalue())
        self.assertNotIn("1234", output.getvalue())
        self.assertNotIn("87654321", output.getvalue())

    def test_cancel_is_explicit_and_redacted(self) -> None:
        output = io.StringIO()
        with mock.patch.object(chase_mfa, "_read_masked_line", return_value="cancel"):
            with self.assertRaises(ChaseMFACancelledError) as raised:
                collect_chase_mfa_code(
                    timeout=30,
                    terminal_factory=_Terminal,  # type: ignore[arg-type]
                    output=output,
                )
        self.assertEqual(str(raised.exception), "Chase authentication cancelled")

    def test_timeout_is_bounded_and_redacted(self) -> None:
        output = io.StringIO()
        with mock.patch.object(
            chase_mfa,
            "_read_masked_line",
            side_effect=ChaseMFATimedOutError(),
        ):
            with self.assertRaises(ChaseMFATimedOutError) as raised:
                collect_chase_mfa_code(
                    timeout=0.01,
                    terminal_factory=_Terminal,  # type: ignore[arg-type]
                    output=output,
                )
        self.assertEqual(str(raised.exception), "Chase authentication timed out")

    def test_non_terminal_input_fails_closed(self) -> None:
        stream = mock.Mock()
        stream.fileno.return_value = 3
        stream.isatty.return_value = False
        with self.assertRaisesRegex(ChaseMFAError, "interactive local terminal"):
            chase_mfa._read_masked_line(stream, io.StringIO(), 1)

    def test_terminal_reader_masks_code_and_restores_state(self) -> None:
        stream = mock.Mock()
        stream.fileno.return_value = 7
        stream.isatty.return_value = True
        output = io.StringIO()
        terminal_state = [object()]
        with (
            mock.patch.object(chase_mfa.termios, "tcgetattr", return_value=terminal_state),
            mock.patch.object(chase_mfa.tty, "setcbreak"),
            mock.patch.object(chase_mfa.select, "select", return_value=([7], [], [])),
            mock.patch.object(chase_mfa.os, "read", side_effect=[*[bytes([value]) for value in b"87654321"], b"\n"]),
            mock.patch.object(chase_mfa.termios, "tcsetattr") as restore,
        ):
            result = chase_mfa._read_masked_line(stream, output, 1)
        self.assertEqual(result, "87654321")
        self.assertEqual(output.getvalue(), "********\n")
        self.assertNotIn(result, output.getvalue())
        restore.assert_called_once_with(7, chase_mfa.termios.TCSADRAIN, terminal_state)

    def test_terminal_eof_fails_closed_and_restores_state(self) -> None:
        stream = mock.Mock()
        stream.fileno.return_value = 7
        stream.isatty.return_value = True
        output = io.StringIO()
        terminal_state = [object()]
        with (
            mock.patch.object(chase_mfa.termios, "tcgetattr", return_value=terminal_state),
            mock.patch.object(chase_mfa.tty, "setcbreak"),
            mock.patch.object(chase_mfa.select, "select", return_value=([7], [], [])),
            mock.patch.object(chase_mfa.os, "read", return_value=b""),
            mock.patch.object(chase_mfa.termios, "tcsetattr") as restore,
        ):
            with self.assertRaisesRegex(ChaseMFAError, "interactive local terminal"):
                chase_mfa._read_masked_line(stream, output, 1)
        restore.assert_called_once_with(7, chase_mfa.termios.TCSADRAIN, terminal_state)

    def test_terminal_state_is_restored_after_timeout(self) -> None:
        stream = mock.Mock()
        stream.fileno.return_value = 7
        stream.isatty.return_value = True
        output = io.StringIO()
        terminal_state = [object()]
        with (
            mock.patch.object(chase_mfa.termios, "tcgetattr", return_value=terminal_state),
            mock.patch.object(chase_mfa.tty, "setcbreak"),
            mock.patch.object(chase_mfa.select, "select", return_value=([], [], [])),
            mock.patch.object(chase_mfa.termios, "tcsetattr") as restore,
        ):
            with self.assertRaises(ChaseMFATimedOutError):
                chase_mfa._read_masked_line(stream, output, 1)
        restore.assert_called_once_with(7, chase_mfa.termios.TCSADRAIN, terminal_state)


if __name__ == "__main__":
    unittest.main()
