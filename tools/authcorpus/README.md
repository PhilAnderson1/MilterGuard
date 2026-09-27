# Authentication corpus comparator

`authcorpus` compares authentication results saved in `.eml` files with fresh
results from MilterGuard's internal Mox verifier. It reads raw message bytes for
DKIM, reconstructs SMTP metadata from `Received` and `Return-Path`, and writes a
mode-0600 JSON report. Message bodies and mailbox addresses are not included in
the report; relative filenames, authentication domains, outcomes, bounded error
categories and latency are included.

Run it from the repository root:

```sh
go run ./tools/authcorpus \
  -directory local-testing/test_emails \
  -output /tmp/milterguard-auth-corpus.json \
  -receiver-ip 127.0.0.1 \
  -message-storage memory
```

`-receiver-ip` supplies the original receiving SMTP interface used by uncommon
SPF macros. Saved messages usually do not retain it; use the real value when it
is known. `-message-storage` accepts `memory` or `file` and exercises the same
exact-message implementations as the Milter.

The command deliberately treats a missing saved method result as unavailable
reference data, not as a disagreement. `outcome_match` compares the method
outcome and alignment conclusion. `details_match` additionally compares the
set of passing domains when the saved result identifies one.

Fresh verification is time-sensitive. DKIM signatures can expire, selectors
can be revoked or removed, and SPF/DMARC policies can change after receipt.
Those results are genuine current verification outcomes, so every difference
must be interpreted using the bounded reasons in the report rather than being
silently accepted or rewritten.
