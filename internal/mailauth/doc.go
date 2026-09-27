// Package mailauth owns provider-neutral SPF, DKIM, and DMARC evidence, the
// authentication verifier boundary, exact-message storage, trusted local
// result parsing, and domain alignment. The trusted-header provider consumes
// results produced by configured local authentication services; internal
// verification performs the cryptographic and DNS policy checks itself.
package mailauth
