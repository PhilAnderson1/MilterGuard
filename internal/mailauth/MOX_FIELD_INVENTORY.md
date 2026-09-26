# Mox authentication field inventory

This Stage 1 inventory is based on Mox v0.0.17. Production code does not import
Mox yet. Stage 2 adapters must translate these values into the bounded
MilterGuard-owned types in this package.

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
| `Sig.Length >= 0` | Preserve as `BodyLengthLimited`; default policy results remain policy and cannot authenticate. |
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
| error | Map to bounded `ErrorCategory` and `Reason`. |
| `Reject` | Do not turn directly into a Milter action. Preserve the published/effective policy fields; rejection remains explicit MilterGuard policy. |
| reporting URIs, intervals, formats and failure options | Discard for initial verification: MilterGuard does not generate DMARC reports and these values can be large. |
| complete TXT record | Discard after translating its bounded semantics. |

All domain strings are normalized before storage. Provider adapters must cap
identity, selector, mechanism and reason lengths and must never place raw Mox
types, DNS records or errors in session, prompt or persistence state.
