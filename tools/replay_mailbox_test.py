import argparse
import email.parser
import email.policy
import io
import json
import struct
import unittest
from pathlib import Path

from tools import replay_mailbox


class ScriptedSocket:
    def __init__(self, responses):
        self.pending = b"".join(
            struct.pack("!I", len(response)) + response for response in responses
        )

    def sendall(self, data):
        pass

    def recv(self, length):
        chunk, self.pending = self.pending[:length], self.pending[length:]
        return chunk


def headers(value):
    return email.parser.Parser(policy=email.policy.compat32).parsestr(value + "\n\n")


class ReceivedConnectionTests(unittest.TestCase):
    def test_extracts_postfix_connection_identities(self):
        parsed = headers(
            "Received: from helo.example (ptr.example [8.8.8.8])\n"
            "\tby mx.example with ESMTPS id 123"
        )
        self.assertEqual(
            replay_mailbox.connection_from_received(parsed),
            {
                "remote_ip": "8.8.8.8",
                "hostname": "ptr.example",
                "helo": "helo.example",
                "mta_hostname": "mx.example",
                "receiver_ip": None,
                "source": "received",
            },
        )

    def test_ignores_private_and_by_clause_addresses(self):
        parsed = headers(
            "Received: from internal.example (internal.example [192.168.1.2])\n"
            "\tby mx.example ([8.8.8.8]) with ESMTP"
        )
        self.assertEqual(
            replay_mailbox.connection_from_received(parsed)["source"], "unavailable"
        )

    def test_uses_first_suitable_external_received_header(self):
        parsed = headers(
            "Received: from local.example (local.example [127.0.0.1]) by mx.example\n"
            "Received: from original.example (original.example [1.1.1.1]) by local.example"
        )
        connection = replay_mailbox.connection_from_received(parsed)
        self.assertEqual(connection["remote_ip"], "1.1.1.1")
        self.assertEqual(connection["hostname"], "original.example")
        self.assertEqual(connection["mta_hostname"], "mx.example")

    def test_connect_macros_include_receiver_identity_and_ip(self):
        self.assertEqual(
            replay_mailbox.connect_macro_payload(
                {"mta_hostname": "mx.example", "receiver_ip": "2001:db8::1"}
            ),
            b"Cj\x00mx.example\x00{daemon_addr}\x002001:db8::1\x00",
        )

    def test_retains_mta_hostname_without_a_public_peer(self):
        parsed = headers(
            "Received: from internal.example (internal.example [192.168.1.2]) "
            "by mx.example with ESMTP"
        )
        connection = replay_mailbox.connection_from_received(parsed)
        self.assertEqual(connection["source"], "unavailable")
        self.assertEqual(connection["mta_hostname"], "mx.example")


class EnvelopeTests(unittest.TestCase):
    def test_reconstructs_envelope_addresses(self):
        parsed = headers(
            "Return-Path: <bounce@example.net>\n"
            "X-Original-To: local@example.org\n"
            "From: Visible Sender <visible@example.net>\n"
            "To: fallback@example.org"
        )
        args = argparse.Namespace(mail_from=None, rcpt_to=None)
        self.assertEqual(
            replay_mailbox.envelope_addresses(parsed, args),
            ("bounce@example.net", "local@example.org"),
        )

    def test_explicit_addresses_take_precedence(self):
        parsed = headers("Return-Path: <saved@example.net>\nTo: saved@example.org")
        args = argparse.Namespace(
            mail_from="override@example.net", rcpt_to="override@example.org"
        )
        self.assertEqual(
            replay_mailbox.envelope_addresses(parsed, args),
            ("override@example.net", "override@example.org"),
        )


class ProgressFrameTests(unittest.TestCase):
    def test_replay_waits_for_decision_after_progress_and_header_frames(self):
        sock = ScriptedSocket(
            [b"c"] * 5
            + [b"p", b"hX-MilterGuard-Classification\x00legitimate\x00", b"p", b"a"]
        )
        result, _, added_headers = replay_mailbox.replay(
            sock, [(b"Subject", b"test")], b"body", "sender@example.net", "user@example.net"
        )
        self.assertEqual(result, ("accept", ""))
        self.assertEqual(added_headers, {"X-MilterGuard-Classification": "legitimate"})


class ExactHeaderReplayTests(unittest.TestCase):
    def test_callback_headers_reconstruct_exact_dkim_fixture(self):
        path = Path(__file__).parents[1] / "prototype" / "exactdkim" / "signed-canonicalizations.eml"
        raw_headers, _ = replay_mailbox.split_message(path.read_bytes())
        callbacks = replay_mailbox.callback_headers(raw_headers)
        reconstructed = b"".join(
            name + b": " + value.replace(b"\n", b"\r\n") + b"\r\n"
            for name, value in callbacks
        )
        self.assertEqual(reconstructed, raw_headers + b"\r\n")

    def test_preserves_duplicate_headers_whitespace_and_folds(self):
        callbacks = replay_mailbox.callback_headers(
            b"From:  Alice <alice@example.org>\r\n"
            b"X-Test:\tvalue \r\n"
            b"X-Test: second\r\n"
            b"\tcontinued\r\n"
        )
        self.assertEqual(
            callbacks,
            [
                (b"From", b" Alice <alice@example.org>"),
                (b"X-Test", b"\tvalue "),
                (b"X-Test", b"second\n\tcontinued"),
            ],
        )


class ReplayOutputTests(unittest.TestCase):
    def test_dots_on_match_preserves_full_mismatches_errors_and_summary(self):
        stream = io.StringIO()
        output = replay_mailbox.ReplayOutput(dots_on_match=True, stream=stream)
        output.result({"file": "a.eml", "matched": True})
        output.result({"file": "b.eml", "matched": True})
        output.result({"file": "c.eml", "matched": False})
        output.result({"file": "d.eml", "matched": True})
        output.result({"file": "e.eml", "result": "error"})
        output.result({"file": "f.eml", "matched": True})
        output.summary({"summary": {"accept": 3}, "mismatches": 1})
        self.assertEqual(
            stream.getvalue(),
            "..\n"
            + json.dumps({"file": "c.eml", "matched": False}) + "\n"
            + ".\n"
            + json.dumps({"file": "e.eml", "result": "error"}) + "\n"
            + ".\n"
            + json.dumps({"summary": {"accept": 3}, "mismatches": 1}) + "\n",
        )

    def test_default_output_remains_json_lines(self):
        stream = io.StringIO()
        output = replay_mailbox.ReplayOutput(stream=stream)
        output.result({"file": "a.eml", "matched": True})
        output.summary({"summary": {"accept": 1}})
        self.assertEqual(
            stream.getvalue(),
            json.dumps({"file": "a.eml", "matched": True}) + "\n"
            + json.dumps({"summary": {"accept": 1}}) + "\n",
        )



if __name__ == "__main__":
    unittest.main()
