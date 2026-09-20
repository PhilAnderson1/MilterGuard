// Package rdap securely discovers and queries RDAP services for domain
// registration dates. It owns HTTP transport, bootstrap caching, redirect
// validation, and DNS-pinned dialing; mail policy and persistence remain with
// its caller.
package rdap
