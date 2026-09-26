// Package systemdns constructs resolvers for MilterGuard's non-authentication
// DNS users.
package systemdns

import "net"

// NewResolver returns a resolver whose behavior is independent of mutations to
// net.DefaultResolver by imported packages. Its zero-value StrictErrors setting
// preserves partial A/AAAA results when one address family temporarily fails.
func NewResolver() *net.Resolver {
	return &net.Resolver{}
}
