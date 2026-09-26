# Mox authentication field inventory

This inventory is based on Mox v0.0.17. `internal/mailauth/moxverify` is the
only production package that imports Mox and translates these values into the
bounded MilterGuard-owned types in its parent package. The runtime composition
root selects this adapter only when `authentication.mode: internal` is set.

## SPF

`spf.Verify` returns `spf.Received`, the evaluated domain, an explanation,
DNS-authenticity and an error.

| Mox value | MilterGuard treatment |
| --- | --- |
| `Received.Result` | Preserve as `Result.Outcome`, including none, neutral, softfail, fail, temperror and permerror. Used by headers, prompts and policy. |
| evaluated domain | Preserve as `Result.Domain`. Used for alignment and display. |
| `Received.Identity` | Preserve as `Result.SPFIdentity` (`mailfrom` or `helo`). |
| `Received.Mechanism` | Preserve in bounded form as `Result.SPFMechanism`; useful diagnostic evidence. |
| DNS authenticity | Preserve as `Result.DNSAuthentic`. |
| error | Map to `ErrorCategory` and a bounded `Reason`; do not retain an unbounded resolver string. |
| explanation/comment/problem | Do not preserve verbatim: remotely influenced and potentially large. A bounded category is sufficient. |
| client IP, envelope-from, HELO and receiver | Do not duplicate in the result; canonical values already belong to `Transaction`. |

## DKIM

`dkim.Verify` returns one `dkim.Result` per signature. The adapter must retain
the order and must not collapse results with the same domain.

| Mox value | MilterGuard treatment |
| --- | --- |
| `Status` | Preserve as `Result.Outcome`, including policy, neutral, temperror and permerror. |
| `Sig.Domain`, `Sig.Selector`, `Sig.Identity` | Preserve as domain, selector and bounded identity. Domain is used for alignment. |
| signing/hash algorithms | Preserve together in `Result.Algorithm`. |
| header/body canonicalization | Preserve separately. Useful for diagnostics and interoperability. |
| `Sig.Length >= 0` | Preserve the presence as `BodyLengthLimited` and the declared value as `BodyLength`; default policy results remain policy and cannot authenticate. |
| `RecordAuthentic` | Preserve as `DNSAuthentic`. |
| error | Map to bounded `ErrorCategory` and `Reason`. |
| signed-header names and query methods | Initially discard as parser detail; they can be numerous and are not policy inputs. |
| signature, body hash, copied headers, public key and complete DNS record | Discard: cryptographic material or attacker-controlled/unbounded detail with no consumer. |
| signing and expiry timestamps | Initially discard; Mox has already applied validity checks and exposes failures through status/error. |
| DNS record notes, services and flags | Preserve only semantic effects through result/category; discard raw values. |

## DMARC

`dmarc.Result` combines the evaluation with the applicable parsed policy.

| Mox value | MilterGuard treatment |
| --- | --- |
| `Status` | Preserve as `Result.Outcome`. |
| `Domain` | Preserve as `PolicyDomain` and result domain. This may be the organizational policy domain. |
| `AlignedSPFPass`, `AlignedDKIMPass` | Preserve independently and use Mox's conclusion for DMARC evidence. |
| record `Policy`, `SubdomainPolicy` | Preserve as bounded dispositions. |
| record `ADKIM`, `ASPF`, `Percentage` | Preserve as alignment modes and policy percentage. |
| `RecordAuthentic` | Preserve as `DNSAuthentic`. |
| `dmarc.Verify` `useResult` | Preserve as `PolicyApplied`; this records percentage sampling without turning Mox's rejection recommendation into a Milter action. |
| error | Map to bounded `ErrorCategory` and `Reason`. |
| `Reject` | Do not turn directly into a Milter action. Preserve the published/effective policy fields; rejection remains explicit MilterGuard policy. |
| reporting URIs, intervals, formats and failure options | Discard for initial verification: MilterGuard does not generate DMARC reports and these values can be large. |
| complete TXT record | Discard after translating its bounded semantics. |

All domain strings are normalized before storage. The adapter retains at most
32 DKIM signature results and adds one resource-limit result if more signatures
were present. Signatures beyond the limit are rejected by policy before DNS or
cryptographic verification. Selectors and domains are capped at 253 bytes,
identities at 320, SPF mechanisms at 256, algorithms at 64, and canonicalization
names at 16. Reasons come from a fixed local vocabulary rather than raw Mox or
resolver errors. Raw Mox types, DNS records and errors never enter session,
prompt or persistence state, and Mox's verbose DNS logging is discarded in
favor of one bounded service summary.

See `MOX_INTEROPERABILITY_MATRIX.md` for the tested status and edge-case matrix,
including Mox's missing-key and multiple-key-record DKIM semantics.

## Authentication-Results output subset

The local RFC 8601 renderer emits one SPF result with `smtp.mailfrom` or
`smtp.helo`, up to 32 ordered DKIM results with validated `header.d`, `header.s`
and `header.a` properties, and one DMARC result with `header.from`. For a DMARC
failure it also emits the registered `policy.dmarc` property with the effective
`none`, `quarantine` or `reject` disposition. Unbounded reason text, DKIM
identity, canonicalization details, body length, DNSSEC state, alignment modes
and percentage metadata remain available in typed evidence but are deliberately
not copied into the field. Invalid outcomes and unsafe property values are
omitted; they are never quoted or repaired into attacker-controlled output.
