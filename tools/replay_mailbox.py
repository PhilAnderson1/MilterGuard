#!/usr/bin/env python3
"""Replay every .eml file in a directory through a test Milter connection."""

import argparse
import email.parser
import email.policy
import email.utils
import ipaddress
import json
import re
import socket
import struct
import sys
import time
from pathlib import Path


def send_frame(sock, payload):
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def receive_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("milter closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_frame(sock):
    header = receive_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    if length < 1 or length > 16 * 1024 * 1024:
        raise RuntimeError(f"invalid milter frame length: {length}")
    return receive_exact(sock, length)


def command(sock, code, payload=b""):
    send_frame(sock, code + payload)
    return receive_frame(sock)


def continue_command(sock, code, payload=b""):
    response = command(sock, code, payload)
    if response != b"c":
        raise RuntimeError(f"unexpected response to {code!r}: {response!r}")


def no_response_command(sock, code, payload=b""):
    send_frame(sock, code + payload)
    previous_timeout = sock.gettimeout()
    try:
        sock.settimeout(0.1)
        unexpected = sock.recv(1)
        if unexpected:
            raise RuntimeError(f"unexpected response to {code!r}: {unexpected!r}")
        raise ConnectionError("milter closed the connection")
    except socket.timeout:
        pass
    finally:
        sock.settimeout(previous_timeout)


def negotiate(sock):
    # Offer ADDHEADER and CHGHEADER so result-header behavior is covered by
    # corpus replay when filtering.add_email_headers is enabled.
    response = command(sock, b"O", struct.pack("!III", 6, 0x11, 0))
    if not response.startswith(b"O"):
        raise RuntimeError(f"unexpected negotiation response: {response!r}")


def begin_smtp_session(sock, connection):
    hostname = connection["hostname"] or "unknown"
    helo = connection["helo"] or "unknown"
    remote_ip = connection["remote_ip"]
    mta_hostname = connection["mta_hostname"]
    if mta_hostname:
        # The Milter j macro identifies the receiving MTA. MilterGuard uses it
        # to decide which saved Authentication-Results headers are local and
        # therefore trustworthy during a replay.
        no_response_command(
            sock,
            b"D",
            b"Cj\x00" + mta_hostname.encode("utf-8", "replace") + b"\x00",
        )
    if remote_ip:
        family = b"6" if ipaddress.ip_address(remote_ip).version == 6 else b"4"
        connect_payload = (
            hostname.encode("utf-8", "replace")
            + b"\x00"
            + family
            + struct.pack("!H", 25)
            + remote_ip.encode("ascii")
            + b"\x00"
        )
    else:
        connect_payload = hostname.encode("utf-8", "replace") + b"\x00U"
    continue_command(sock, b"C", connect_payload)
    continue_command(sock, b"H", helo.encode("utf-8", "replace") + b"\x00")

    # Exercise the transaction reset used when an SMTP session starts again
    # after STARTTLS. SMFIC_ABORT has no response.
    no_response_command(sock, b"A")
    continue_command(sock, b"H", helo.encode("utf-8", "replace") + b"\x00")


def split_message(raw):
    marker = b"\r\n\r\n"
    position = raw.find(marker)
    if position < 0:
        marker = b"\n\n"
        position = raw.find(marker)
    if position < 0:
        return raw, b""
    return raw[:position], raw[position + len(marker) :]


def load_message(path):
    raw = path.read_bytes()
    header_bytes, body = split_message(raw)
    parsed = email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(
        header_bytes + b"\n\n"
    )
    return parsed, body


def clean_identity(value):
    if value is None:
        return None
    value = " ".join(str(value).replace("\x00", "").split()).strip("<>[]")
    if not value or value.lower() == "unknown":
        return None
    return value[:255]


def connection_from_received(parsed):
    mta_hostname = None
    for header in parsed.get_all("Received", []):
        value = " ".join(str(header).split())
        clauses = re.split(r"\s+by\s+", value, maxsplit=1, flags=re.I)
        from_clause = clauses[0]
        if mta_hostname is None and len(clauses) == 2:
            by_fields = clauses[1].split(None, 1)
            if by_fields:
                mta_hostname = clean_identity(by_fields[0])
        addresses = re.findall(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", from_clause, re.I)
        remote_ip = None
        for candidate in addresses:
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if address.is_global:
                remote_ip = address.compressed
                break
        if remote_ip is None:
            continue

        match = re.search(r"(?:^|\s)from\s+([^\s(]+)(?:\s+\((.*?)\))?", from_clause, re.I)
        helo = clean_identity(match.group(1)) if match else None
        hostname = None
        if match and match.group(2):
            before_address = re.split(r"\[(?:IPv6:)?[0-9A-Fa-f:.]+\]", match.group(2), maxsplit=1, flags=re.I)[0]
            candidates = [clean_identity(item) for item in before_address.split()]
            candidates = [item for item in candidates if item]
            if candidates:
                hostname = candidates[-1]
        return {
            "remote_ip": remote_ip,
            "hostname": hostname,
            "helo": helo,
            "mta_hostname": mta_hostname,
            "source": "received",
        }
    return {
        "remote_ip": None,
        "hostname": None,
        "helo": None,
        "mta_hostname": mta_hostname,
        "source": "unavailable",
    }


def replay_connection(parsed, args):
    if args.connection_info == "received":
        connection = connection_from_received(parsed)
    else:
        connection = {
            "remote_ip": "127.0.0.1",
            "hostname": "replay.local",
            "helo": "replay.local",
            "mta_hostname": "replay.local",
            "source": "synthetic",
        }
    if args.remote_ip is not None:
        try:
            connection["remote_ip"] = ipaddress.ip_address(args.remote_ip).compressed
        except ValueError as exc:
            raise ValueError(f"invalid --remote-ip: {args.remote_ip}") from exc
        connection["source"] = "override"
    if args.client_hostname is not None:
        connection["hostname"] = clean_identity(args.client_hostname)
        connection["source"] = "override"
    if args.helo is not None:
        connection["helo"] = clean_identity(args.helo)
        connection["source"] = "override"
    if args.mta_hostname is not None:
        connection["mta_hostname"] = clean_identity(args.mta_hostname)
        connection["source"] = "override"
    return connection


def envelope_addresses(parsed, args):
    if args.mail_from is not None:
        mail_from = args.mail_from
    elif parsed.get("Return-Path") is not None:
        mail_from = email.utils.parseaddr(str(parsed.get("Return-Path")))[1]
    else:
        mail_from = email.utils.parseaddr(str(parsed.get("From", "")))[1]
    if not mail_from and parsed.get("Return-Path") is None:
        mail_from = "replay-sender@example.invalid"

    rcpt_to = args.rcpt_to
    if rcpt_to is None:
        for header in ("X-Original-To", "Delivered-To", "To"):
            rcpt_to = email.utils.parseaddr(str(parsed.get(header, "")))[1]
            if rcpt_to:
                break
    if not rcpt_to:
        rcpt_to = "replay-recipient@example.invalid"
    return mail_from, rcpt_to


def replay(sock, parsed, body, mail_from, rcpt_to):

    started = time.monotonic()
    response = command(sock, b"M", f"<{mail_from}>\x00".encode("ascii"))
    if response != b"c":
        elapsed_ms = round((time.monotonic() - started) * 1000)
        return interpret(response), elapsed_ms, {}
    continue_command(sock, b"R", f"<{rcpt_to}>\x00".encode("ascii"))

    for name, value in parsed.raw_items():
        clean_name = name.replace("\x00", "").encode("utf-8", "replace")
        clean_value = value.replace("\x00", "").encode("utf-8", "replace")
        response = command(sock, b"L", clean_name + b"\x00" + clean_value + b"\x00")
        if response != b"c":
            raise RuntimeError(f"header rejected unexpectedly: {response!r}")

    continue_command(sock, b"N")

    for offset in range(0, len(body), 64 * 1024):
        response = command(sock, b"B", body[offset : offset + 64 * 1024])
        if response != b"c":
            raise RuntimeError(f"body rejected unexpectedly: {response!r}")

    started = time.monotonic()
    send_frame(sock, b"E")
    added_headers = {}
    while True:
        response = receive_frame(sock)
        if response.startswith(b"h"):
            fields = response[1:].split(b"\x00")
            if len(fields) != 3 or fields[-1] != b"":
                raise RuntimeError(f"malformed SMFIR_ADDHEADER: {response!r}")
            name = fields[0].decode("utf-8", "replace")
            value = fields[1].decode("utf-8", "replace")
            added_headers[name] = value
            continue
        if response.startswith(b"m"):
            # CHGHEADER removes any sender-forged MilterGuard result headers.
            continue
        elapsed_ms = round((time.monotonic() - started) * 1000)
        return interpret(response), elapsed_ms, added_headers


def interpret(response):
    if response == b"a":
        return "accept", ""
    if response == b"r":
        return "reject", ""
    if response == b"t":
        return "tempfail", ""
    if response.startswith(b"y"):
        payload = response[1:]
        if not payload.endswith(b"\x00") or b"\x00" in payload[:-1]:
            return "unknown", f"malformed SMFIR_REPLYCODE: {response!r}"
        detail = payload[:-1].decode("utf-8", "replace")
        if not re.fullmatch(
            r"[45][0-9]{2} (?:[245]\.[0-9]{1,3}\.[0-9]{1,3} )?[^\r\n]+", detail
        ):
            return "unknown", f"malformed SMFIR_REPLYCODE: {response!r}"
        return ("reject" if detail.startswith("5") else "tempfail"), detail
    return "unknown", repr(response)


def message_files(directory):
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() == ".eml":
            yield path


def main():
    parser = argparse.ArgumentParser(
        description="Replay a directory of .eml files through a test MilterGuard instance."
    )
    parser.add_argument("directory", type=Path, help="directory containing .eml files")
    parser.add_argument("--host", default="127.0.0.1", help="Milter host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8894, help="Milter port (default: 8894)")
    parser.add_argument(
        "--connection-info",
        choices=("received", "synthetic"),
        default="received",
        help="derive connection metadata from Received headers or use replay.local (default: received)",
    )
    parser.add_argument("--remote-ip", help="override the reconstructed SMTP peer IP")
    parser.add_argument("--client-hostname", help="override the reconstructed MTA-reported hostname")
    parser.add_argument("--helo", help="override the reconstructed SMTP HELO/EHLO identity")
    parser.add_argument(
        "--mta-hostname",
        help="override the receiving MTA hostname used to trust saved authentication results",
    )
    parser.add_argument("--mail-from", help="override Return-Path/From envelope-sender reconstruction")
    parser.add_argument("--rcpt-to", help="override X-Original-To/Delivered-To/To recipient reconstruction")
    parser.add_argument("--expected", choices=("accept", "reject"))
    parser.add_argument("--timeout", type=float, default=90, help="socket timeout in seconds")
    args = parser.parse_args()

    if not args.directory.is_dir():
        parser.error(f"not a directory: {args.directory}")

    totals = {"accept": 0, "reject": 0, "tempfail": 0, "unknown": 0, "error": 0}
    mismatches = 0
    files = list(message_files(args.directory))
    if not files:
        parser.error("no .eml files found")

    for path in files:
        try:
            parsed, body = load_message(path)
            connection = replay_connection(parsed, args)
            mail_from, rcpt_to = envelope_addresses(parsed, args)
            with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
                sock.settimeout(args.timeout)
                negotiate(sock)
                begin_smtp_session(sock, connection)
                (result, detail), latency, added_headers = replay(
                    sock, parsed, body, mail_from, rcpt_to
                )
                send_frame(sock, b"Q")
                totals[result] += 1
                matched = args.expected is None or result == args.expected
                mismatches += int(not matched)
                print(
                    json.dumps(
                        {
                            "file": str(path),
                            "result": result,
                            "expected": args.expected,
                            "matched": matched,
                            "latency_ms": latency,
                            "detail": detail,
                            "added_headers": added_headers,
                            "connection": connection,
                            "mail_from": mail_from,
                            "rcpt_to": rcpt_to,
                        }
                    ),
                    flush=True,
                )
        except Exception as exc:
            totals["error"] += 1
            mismatches += int(args.expected is not None)
            print(
                json.dumps({"file": str(path), "result": "error", "error": str(exc)}),
                flush=True,
            )

    print(
        json.dumps(
            {"summary": totals, "expected": args.expected, "mismatches": mismatches}
        ),
        flush=True,
    )
    return 1 if mismatches or totals["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
