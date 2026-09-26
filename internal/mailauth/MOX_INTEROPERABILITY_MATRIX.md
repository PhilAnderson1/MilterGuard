# Mox authentication interoperability matrix

Tested version: Mox v0.0.17

The adapter tests are deterministic and use Mox's resolver interface with local
records. They exercise MilterGuard's input adaptation, Mox verification and the
translation back to bounded `mailauth` evidence. They do not replace the later
saved-message comparison against OpenDKIM and OpenDMARC.

## SPF

Covered inputs and mechanisms:

- IPv4, IPv6, IDNA envelope domains, null reverse paths, domain HELO and IPv4
  and IPv6 HELO literals.
- `ip4`, `ip6`, `include`, `redirect`, `a`, `mx`, `exists` and `all`.
- Sender local-part/domain, HELO, receiver/local address and reversed-IP macro
  expansion, plus a macro that is invalid in mechanism context.
- Pass, neutral, softfail, fail, none, temperror and permerror results.
- Recursive-include and void-lookup limits, malformed policy and temporary DNS
  failure.

Mox enforces the RFC lookup limits. MilterGuard preserves the Mox status and
uses a local resource-limit category for request/void-limit failures. It does
not retain the remotely supplied SPF explanation string.

## DKIM

Covered inputs and algorithms:

- RSA-SHA256 and Ed25519-SHA256, including an SMTPUTF8 signing identity.
- Simple/simple, simple/relaxed, relaxed/simple and relaxed/relaxed
  canonicalization.
- Folded and repeated headers, empty bodies, binary-looking MIME bodies,
  modified bodies, mixed passing/failing signatures and an injected header
  protected by oversigning.
- Missing, duplicate and temporarily unavailable key records; unsupported
  algorithms; negative, duplicate and overflowing `l=` values.
- A valid `l=` signature rejected by Mox's default policy with the declared
  length retained in evidence.

Mox v0.0.17 deliberately returns `permerror` for a missing DKIM key and
`temperror` for multiple valid key records. MilterGuard preserves those
statuses. The former receives the bounded `lookup` category; the latter is
categorized as remote syntax/configuration rather than a DNS transport error.

At most 32 syntactically valid signatures reach DNS and cryptographic
verification. At most 32 individual results plus one resource-limit summary
are retained. Results beyond the limit cannot authenticate the message or
contribute to DMARC.

## DMARC

Covered policy behavior:

- SPF and DKIM pass/fail alignment with relaxed and strict modes.
- Organizational-domain fallback, `p`, `sp`, and deterministic `pct=0` and
  `pct=100` behavior.
- Pass, fail, none, temperror and permerror results.
- Missing, malformed, multiple and temporarily unavailable policy records.
- Missing/ambiguous visible From identity, which suppresses DMARC evaluation.

The adapter preserves Mox's aligned-SPF/aligned-DKIM conclusions, policy
domain, alignment modes, dispositions, percentage and sampled-policy decision.
Mox's rejection recommendation is not converted into a Milter action.

## Saved-corpus and load follow-up

The representative legitimate, spam, scam and deliberately failing corpus has
been compared with saved OpenDKIM/OpenDMARC-era results. Every disagreement and
the ordinary-message memory/latency sample are documented in
`CORPUS_COMPARISON.md`. A deterministic unavailable-resolver load test covers
queue deadlines, lookup concurrency and cleanup under the race detector.

Configured maximum-message/maximum-connection stress and the production
same-time observation period remain rollout checks.
