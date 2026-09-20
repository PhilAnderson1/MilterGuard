// Package mailauth parses authentication evidence added by trusted local mail
// services and evaluates DKIM, SPF, and DMARC domain alignment. It does not
// itself perform cryptographic authentication or DNS policy checks.
package mailauth
