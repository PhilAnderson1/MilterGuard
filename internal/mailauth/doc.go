// Package mailauth owns provider-neutral SPF, DKIM, and DMARC evidence, the
// authentication verifier boundary, exact-message storage, trusted local
// result parsing, safe RFC 8601 result rendering, and domain alignment. The
// Stage 1 compatibility provider does not itself perform cryptographic
// authentication or DNS policy checks.
package mailauth
