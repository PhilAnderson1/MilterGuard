# Saved-message authentication comparison

Comparison date: 2026-09-26

## Scope and method

The local corpus contains 104 CRLF-preserved messages: 64 legitimate, 13 spam,
23 scam and 4 deliberately failing variants. Eighty messages have a saved DKIM
result, 10 have a saved SPF result and 9 have a saved DMARC result that the
compatibility provider can parse. Three messages lack at least one item of
reconstructable SMTP or visible-From metadata; one of those cannot be used for
a meaningful SPF comparison.

`tools/authcorpus` passed each raw message to the production Mox adapter and
parsed saved `Authentication-Results`/`Received-SPF` fields through the
header-backed provider. DNS was resolved live, with a 20-second per-message
deadline and eight-message concurrency bound. The original receiving interface
was not retained by the corpus, so loopback was supplied as the local SPF
interface; this affects only policies that use receiver macros. The detailed
mode-0600 JSON reports remain local under `/tmp` and are not repository assets.

## Results

There were no verifier, message-read or storage errors.

| Method | Saved comparisons | Same outcome/alignment | Different outcome/alignment | Passing-domain-only differences |
| --- | ---: | ---: | ---: | ---: |
| SPF | 10 | 5 | 5 | 1 |
| DKIM | 80 | 33 | 47 | 1 |
| DMARC | 9 | 7 | 2 | 1 |

The differences are understood:

- Forty-six saved DKIM passes now produce `permerror`. Across those messages,
  bounded diagnostics identify 21 expired-signature occurrences, 20 revoked-
  key occurrences and 6 unavailable-key occurrences; a message can contain
  more than one affected signature. These are expected temporal differences
  when old messages are checked against the current clock and current DNS.
- One deliberately failing corpus variant changes a saved DKIM pass into a
  cryptographic failure, as expected. No unmodified message with a currently
  usable, unexpired key produced an unexplained cryptographic failure.
- Two saved SPF failures now evaluate as `softfail` through `~all`, and two
  saved passes now evaluate as `none` for the same identity. The current DNS
  policies differ from the policies recorded at receipt. One further saved SPF
  pass is inconclusive because peer, HELO and envelope metadata are absent.
- Two saved DMARC passes now evaluate as `none`; the live policy lookup no
  longer finds the historical policy. Passing-domain detail differences come
  from additional historical signatures/results and do not change the aligned
  pass conclusion.

This satisfies the saved-corpus comparison gate: every semantic disagreement
is attributable to deliberately modified content, incomplete saved SMTP data,
signature lifetime, or mutable DNS state. It does not replace the planned
production observation period, where current internal and legacy results can
be calculated at the same time.

## Storage and latency sample

Both exact-message modes produced identical method results for all 104
messages, and file mode left no visible `milterguard-exact-message-*` files.
The corpus is 4.8 MiB in total and its largest message is about 368 KiB, so
these figures characterize ordinary saved mail rather than the configured
10 MiB worst case.

| Storage | Wall time | Peak RSS | Median verification | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: |
| memory | 4.75 s | 21,868 KiB | 73 ms | 492 ms | 3,673 ms |
| unlinked file | 4.16 s | 21,248 KiB | 73 ms | 386 ms | 3,174 ms |

The runs used live DNS sequentially, so the small latency and RSS differences
must not be interpreted as a performance ranking. A deterministic unavailable-
resolver load test launches 64 simultaneous verification requests with four
slots and a common 100 ms deadline. It confirms at most four active DNS
lookups, prevents expired queued requests from starting resolver work, and
drains without leaked work under the race detector.

Configured maximum-message/maximum-connection stress and the production
same-time observation period remain rollout checks.
