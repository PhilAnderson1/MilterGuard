import argparse
import email.parser
import email.policy
import unittest

from tools import replay_mailbox


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


if __name__ == "__main__":
    unittest.main()
