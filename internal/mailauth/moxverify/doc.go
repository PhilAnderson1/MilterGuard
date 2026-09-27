// Package moxverify adapts Mox SPF, DKIM, and DMARC verification to
// MilterGuard's provider-neutral mailauth evidence model. Mox types, DNS
// records, and errors do not cross this package boundary; results are reduced
// to bounded MilterGuard-owned values before they reach policy or prompts.
//
// The verifier owns a dedicated strict DNS resolver and bounds verification
// time, concurrency, retained signatures, and diagnostic text. Importing Mox
// changes net.DefaultResolver.StrictErrors, so other MilterGuard DNS users must
// continue to use explicit resolvers from internal/systemdns.
//
// Mox is a pre-v1 dependency. Upgrades require review of its API, result
// semantics, initialization side effects, dependency licences, and the
// interoperability tests in this package.
package moxverify
