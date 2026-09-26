# Exact-DKIM feasibility report

Status: **PASS — exact-DKIM feasibility gate satisfied** (2026-09-26).

Stage 1 has not been started. The callback representation is feasible for the
tested corpus. The earlier `l=` concern is resolved as an
intentional policy decision: Mox's default policy rejects signatures that
authenticate only a body prefix, and MilterGuard will not grant authentication
privileges from them. All required prototype tests now meet the plan's go/no-go
criteria; Stage 1 may begin as a separate next step.

## Environment

- Postfix 3.5.8, run as a separate loopback-only instance on port 2526 with a
  private queue under `/tmp`.
- Mox `github.com/mjl-/mox` v0.0.17.
- No production MilterGuard code or system Postfix configuration was changed.

## Results

The reference `.eml` containing four signatures produced these Mox results:

| Canonicalization | Complete `.eml` | Reassembled callbacks |
| --- | --- | --- |
| simple/simple | pass | pass |
| simple/relaxed | pass | pass |
| relaxed/simple | pass | pass |
| relaxed/relaxed | pass | pass |

The remaining corpus produced matching complete-message and callback results:

| Fixture | Complete `.eml` | Reassembled callbacks |
| --- | --- | --- |
| empty body | pass | pass |
| 4 KiB deterministic binary MIME payload | pass | pass |
| body-length (`l=12`) | policy | policy |

The same message contains folded headers, repeated signed headers, multiple
signatures, trailing body whitespace, and trailing empty lines. Postfix body
callbacks retained the SMTP CRLF bytes in the test.

A separately generated, cryptographically valid `simple/simple` signature with
`l=12` initially produced the following result from both the complete `.eml`
and callback form when the prototype deliberately supplied a permissive policy:

```text
l= (length) parameter in signature not yet implemented
```

This is not callback corruption. Production integration will use Mox's default
policy, which rejects `l=` before that branch and classifies it as `policy`.
The prototype now uses that default policy and both representations produce the
same intentional result:

```text
dkim=policy reason="l= for length not acceptable"
```

An `l=` signature cannot contribute to DKIM alignment, DMARC pass,
sender-domain or correspondent bypasses, or correspondent learning. Its
bounded signing metadata and policy reason should remain available for logging
and locally generated authentication evidence.

## Required callback representation

For syntactically valid RFC 5322 fields in this Postfix path, exact input for
Mox was recovered as follows:

1. Preserve callback header order, duplicates, original field-name spelling,
   and the value verbatim.
2. Reassemble each field as `name + ": " + value + "\r\n"`.
3. Convert the LF characters used inside a folded callback value back to CRLF.
4. Append one CRLF at end-of-headers.
5. Append body callback payloads byte-for-byte, in callback order.

Postfix removes the single header separator space when constructing the Milter
name/value callback. Adding it back is necessary: using `name + ":" + value`
breaks `simple` header canonicalization. Whitespace before a colon is discarded,
but that syntax is invalid under RFC 5322 and is not part of the valid fixture
result.

The reassembled byte stream works directly with `bytes.Reader` and `os.File`,
both of which implement `io.ReaderAt`. It does not use `Message.ArchiveBytes()`.

Postfix added `Message-Id` and `Date` fields before callbacks in this isolated
SMTP test. It did not expose its own `Received` field to this Milter. The added
unsigned fields did not invalidate any signature.

## Milter-chain mutation result

An earlier Milter in the same `smtpd_milters` chain requested both replacement
of the signed `Subject` field and addition of `X-Earlier-Milter` at EOM. Postfix
accepted the message and the mutation responses, but the downstream capture
still received the original Subject and did not receive the added field. All
four original signatures therefore passed in the downstream callback form.

Postfix applies Milter EOM modifications after the inspection callbacks for the
chain rather than feeding each Milter's modified representation to the next
Milter. Consequently, ordering MilterGuard after a modifying Milter does not
make it verify the ultimately modified message. Production configuration must
not permit another before-queue Milter to modify DKIM-signed headers or body
after authentication verification. Adding an unsigned header is harmless to
the tested signatures, but replacing a signed field makes the eventual message
differ from what MilterGuard authenticated.

## Storage observation

A 1 MiB `ReaderAt` microbenchmark (100 iterations) measured:

| Path | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| memory `ReadAt` | 7.27 | 0 | 0 |
| file `ReadAt` | 1,116 | 0 | 0 |
| create/write/close file | 1,893,502 | 984 | 12 |

Both approaches can enforce `milter.max_message_size` while writing
incrementally. Memory storage has the documented worst-case aggregate bound;
file storage avoids duplicating the maximum message in connection memory.

## Gate conclusion

The complete and callback forms agree for all required fixtures, including all
four canonicalization combinations, folded and repeated signed headers,
multiple signatures, body whitespace and empty lines, an empty body, and a
binary MIME payload. The intentional `l=` policy result also agrees. This is a
GO for Stage 1, subject to the Milter-chain mutation constraint above.

An OpenDKIM cross-check was not included in the gate result. The fixtures use a
locally generated key supplied through Mox's mock DNS resolver, while the
available OpenDKIM command-line verifier resolves the selector through DNS and
does not offer an equivalent injected-resolver path. Mox complete-message
verification is the independent reference required by the plan.
