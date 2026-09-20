package milter

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func canonicalIPPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	addr, bits := prefix.Addr(), prefix.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, false
		}
		addr, bits = addr.Unmap(), bits-96
	} else if addr.Is6() {
		addr = addr.WithZone("")
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

// ipReputationStore applies Milter policy around the persistent repository.
type ipReputationStore struct {
	repository      stores.IPReputationRepository
	enabledFeature  bool
	allowlist       []netip.Prefix
	domainAllowlist []string
	log             *slog.Logger
}

// newIPReputationStore adds configured IP and reverse-DNS exclusions around
// the persistent strike and block repository.
func newIPReputationStore(cfg config.IPReputationConfig, repository stores.IPReputationRepository, log *slog.Logger) *ipReputationStore {
	policy := &ipReputationStore{repository: repository, enabledFeature: ipReputationFeaturesEnabled(cfg), log: log}
	for _, entry := range cfg.IPAllowlist {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			if prefix, ok := canonicalIPPrefix(prefix); ok {
				policy.allowlist = append(policy.allowlist, prefix)
			}
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			bits := 128
			if addr.Is4() || addr.Is4In6() {
				bits = 32
			}
			policy.allowlist = append(policy.allowlist, netip.PrefixFrom(netsafety.CanonicalIP(addr), bits))
		}
	}
	for _, domain := range cfg.DomainAllowlist {
		policy.domainAllowlist = append(policy.domainAllowlist, normalizeDomain(domain))
	}
	return policy
}

func ipReputationFeaturesEnabled(cfg config.IPReputationConfig) bool {
	return cfg.MaxEntries > 0 && (cfg.BlockDuration.Value() > 0 || cfg.RepeatThreshold > 0)
}

func (s *ipReputationStore) enabled() bool {
	return s != nil && s.repository != nil && s.enabledFeature
}

var _ stores.IPReputationRepository = (*ipReputationStore)(nil)

func (s *ipReputationStore) allowed(addr netip.Addr) (netip.Prefix, bool) {
	if !addr.IsValid() {
		return netip.Prefix{}, true
	}
	addr = netsafety.CanonicalIP(addr)
	for _, prefix := range s.allowlist {
		if prefix.Contains(addr) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

// add records one AI or deterministic sender-domain rejection unless the
// address or its confirmed reverse-DNS domain is excluded from reputation.
func (s *ipReputationStore) add(ctx context.Context, addr netip.Addr, dns connectionDNSResult) bool {
	if !s.enabled() || !addr.IsValid() {
		return false
	}
	addr = netsafety.CanonicalIP(addr)
	if prefix, ok := s.allowed(addr); ok {
		s.debug("sending IP excluded from rejection reputation", "remote_ip", addr.String(), "matched_prefix", prefix.String(), "reason", "ip_allowlist")
		return false
	}
	if hostname, domain, ok := s.domainAllowed(dns); ok {
		s.debug("sending IP excluded from rejection reputation", "remote_ip", addr.String(), "reverse_dns", hostname, "matched_domain", domain, "reason", "domain_allowlist")
		return false
	}
	block, err := s.repository.RecordRejection(ctx, addr)
	if err != nil {
		s.logDatabaseError("add sending IP strike", err)
		return false
	}
	s.debug("sending IP reputation updated", "remote_ip", addr.String(), "block_level", block.Level, "strike_count", block.StrikeCount, "block_expires_at", block.ExpiresAt)
	return block.Level != ""
}

func (s *ipReputationStore) lookup(ctx context.Context, addr netip.Addr) (stores.IPBlock, bool) {
	block, found, err := s.ActiveBlock(ctx, addr)
	if err != nil {
		s.logDatabaseError("look up sending IP reputation", err)
		return stores.IPBlock{}, false
	}
	return block, found
}

func (s *ipReputationStore) RecordRejection(ctx context.Context, addr netip.Addr) (stores.IPBlock, error) {
	if !s.enabled() || !addr.IsValid() {
		return stores.IPBlock{}, nil
	}
	addr = netsafety.CanonicalIP(addr)
	if _, ok := s.allowed(addr); ok {
		return stores.IPBlock{}, nil
	}
	return s.repository.RecordRejection(ctx, addr)
}

func (s *ipReputationStore) RecordLegitimate(ctx context.Context, addr netip.Addr) error {
	if !s.enabled() || !addr.IsValid() {
		return nil
	}
	return s.repository.RecordLegitimate(ctx, netsafety.CanonicalIP(addr))
}

func (s *ipReputationStore) ActiveBlock(ctx context.Context, addr netip.Addr) (stores.IPBlock, bool, error) {
	if !s.enabled() || !addr.IsValid() {
		return stores.IPBlock{}, false, nil
	}
	addr = netsafety.CanonicalIP(addr)
	if _, ok := s.allowed(addr); ok {
		return stores.IPBlock{}, false, nil
	}
	return s.repository.ActiveBlock(ctx, addr)
}

func (s *ipReputationStore) AddManualBlock(ctx context.Context, addr netip.Addr) (stores.IPBlock, error) {
	if !s.enabled() || !addr.IsValid() {
		return stores.IPBlock{}, fmt.Errorf("IP reputation blocking is disabled or the address is invalid")
	}
	addr = netsafety.CanonicalIP(addr)
	if prefix, ok := s.allowed(addr); ok {
		return stores.IPBlock{}, fmt.Errorf("IP address is protected by allowlist %s", prefix)
	}
	return s.repository.AddManualBlock(ctx, addr)
}

func (s *ipReputationStore) Delete(ctx context.Context, addr netip.Addr) (bool, error) {
	if !s.enabled() {
		return false, fmt.Errorf("IP reputation blocking is disabled or unavailable")
	}
	return s.repository.Delete(ctx, netsafety.CanonicalIP(addr))
}

func (s *ipReputationStore) ListActiveBlocks(ctx context.Context, query stores.IPBlockListQuery) (stores.IPBlockPage, error) {
	if !s.enabled() {
		return stores.IPBlockPage{}, nil
	}
	return s.repository.ListActiveBlocks(ctx, query)
}

func (s *ipReputationStore) domainAllowed(dns connectionDNSResult) (string, string, bool) {
	if len(s.domainAllowlist) == 0 || dns.status != message.ReverseDNSAvailable {
		return "", "", false
	}
	for _, entry := range dns.names {
		if entry.Confirmation != message.ForwardConfirmed {
			continue
		}
		hostname := normalizeDomain(entry.Hostname)
		for _, domain := range s.domainAllowlist {
			if domainMatches(hostname, domain) {
				return hostname, domain, true
			}
		}
	}
	return "", "", false
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func domainMatches(hostname, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, "."+domain)
}

func (s *ipReputationStore) debug(msg string, attrs ...any) {
	if s != nil && s.log != nil {
		s.log.Debug(msg, attrs...)
	}
}

func (s *ipReputationStore) logDatabaseError(operation string, err error) {
	if s != nil && s.log != nil && err != nil {
		s.log.Error("IP reputation database operation failed", "operation", operation, "error", err)
	}
}
