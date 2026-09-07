package milter

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

func TestRejectedIPCacheExpiresEntries(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration: config.Duration(10 * time.Minute),
		MaxEntries:    10,
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.10")
	if !cache.add(addr, "unwanted", 1, connectionDNSResult{}) {
		t.Fatal("IP was not added")
	}
	if _, ok := cache.lookup(addr); !ok {
		t.Fatal("IP was not found before expiry")
	}
	now = now.Add(10 * time.Minute)
	if _, ok := cache.lookup(addr); ok {
		t.Fatal("IP remained cached at its expiry time")
	}
}

func TestRejectedIPCacheHonorsAllowlist(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration: config.Duration(time.Hour),
		MaxEntries:    10,
		IPAllowlist:   []string{"192.0.2.0/24", "2001:db8::1"},
	}, logger)
	for _, value := range []string{"192.0.2.25", "2001:db8::1"} {
		if cache.add(netip.MustParseAddr(value), "unwanted", 1, connectionDNSResult{}) {
			t.Errorf("allowlisted address %s was added", value)
		}
	}
	if !cache.add(netip.MustParseAddr("198.51.100.25"), "unwanted", 1, connectionDNSResult{}) {
		t.Fatal("non-allowlisted address was not added")
	}
	logOutput := output.String()
	for _, wanted := range []string{
		`"msg":"sending IP excluded from rejection reputation","remote_ip":"192.0.2.25","matched_prefix":"192.0.2.0/24","reason":"ip_allowlist","cache_size":0`,
		`"msg":"sending IP excluded from rejection reputation","remote_ip":"2001:db8::1","matched_prefix":"2001:db8::1/128","reason":"ip_allowlist","cache_size":0`,
	} {
		if !strings.Contains(logOutput, wanted) {
			t.Errorf("debug log does not contain %s: %s", wanted, logOutput)
		}
	}
}

func TestRejectedIPCacheEvictsEarliestExpiry(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration: config.Duration(10 * time.Minute),
		MaxEntries:    2,
	}, nil)
	cache.now = func() time.Time { return now }
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	third := netip.MustParseAddr("192.0.2.3")
	cache.add(first, "unwanted", 1, connectionDNSResult{})
	now = now.Add(time.Minute)
	cache.add(second, "unwanted", 1, connectionDNSResult{})
	now = now.Add(time.Minute)
	cache.add(third, "unwanted", 1, connectionDNSResult{})
	if _, ok := cache.lookup(first); ok {
		t.Fatal("earliest-expiring entry was not evicted")
	}
	for _, addr := range []netip.Addr{second, third} {
		if _, ok := cache.lookup(addr); !ok {
			t.Errorf("expected %s to remain cached", addr)
		}
	}
}

func TestRejectedIPCacheShortBlockDoesNotRefreshOnAttempt(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration: config.Duration(time.Minute),
		MaxEntries:    10,
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.10")
	cache.add(addr, "unwanted", 1, connectionDNSResult{})

	now = now.Add(45 * time.Second)
	entry, ok := cache.lookup(addr)
	if !ok {
		t.Fatal("IP was not found before its original expiry")
	}
	wantExpiry := now.Add(15 * time.Second)
	if !entry.expires.Equal(wantExpiry) {
		t.Fatalf("fixed expiry = %v, want %v", entry.expires, wantExpiry)
	}

	now = now.Add(30 * time.Second)
	if _, ok := cache.lookup(addr); ok {
		t.Fatal("short block was refreshed by a cached attempt")
	}
}

func TestRejectedIPCacheLogsSizeOnAddAndRemove(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration: config.Duration(time.Minute),
		MaxEntries:    1,
	}, logger)
	cache.now = func() time.Time { return now }
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	cache.add(first, "unwanted", 1, connectionDNSResult{})
	cache.add(second, "unwanted", 0.95, connectionDNSResult{})
	now = now.Add(time.Minute)
	cache.lookup(second)

	logOutput := output.String()
	for _, wanted := range []string{
		`"msg":"sending IP reputation updated","remote_ip":"192.0.2.1"`,
		`"remote_ip":"192.0.2.1","reason":"capacity","cache_size":0`,
		`"msg":"sending IP reputation updated","remote_ip":"192.0.2.2"`,
		`"msg":"sending IP short block expired","remote_ip":"192.0.2.2"`,
	} {
		if !strings.Contains(logOutput, wanted) {
			t.Errorf("debug log does not contain %s: %s", wanted, logOutput)
		}
	}
}

func TestRejectedIPCacheHonorsForwardConfirmedDomainAllowlist(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.25")
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration:   config.Duration(time.Hour),
		MaxEntries:      10,
		DomainAllowlist: []string{"outlook.com"},
	}, nil)
	dns := connectionDNSResult{
		status: message.ReverseDNSAvailable,
		names:  []message.ReverseDNSName{{Hostname: "mail.outbound.protection.outlook.com", Confirmation: message.ForwardConfirmed}},
	}
	if cache.add(addr, "unwanted", 1, dns) {
		t.Fatal("forward-confirmed outlook.com subdomain was blacklisted")
	}
	if _, found := cache.lookup(addr); found {
		t.Fatal("domain-allowlisted address was present in cache")
	}
}

func TestDomainAllowlistRequiresLabelBoundaryAndForwardConfirmation(t *testing.T) {
	tests := []struct {
		name         string
		hostname     string
		confirmation string
	}{
		{name: "suffix without label boundary", hostname: "eviloutlook.com", confirmation: message.ForwardConfirmed},
		{name: "unconfirmed matching PTR", hostname: "outbound.protection.outlook.com", confirmation: message.ForwardUnconfirmed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr := netip.MustParseAddr("192.0.2.25")
			cache := newIPReputationStore(config.IPReputationConfig{
				BlockDuration:   config.Duration(time.Hour),
				MaxEntries:      10,
				DomainAllowlist: []string{"outlook.com"},
			}, nil)
			dns := connectionDNSResult{
				status: message.ReverseDNSAvailable,
				names:  []message.ReverseDNSName{{Hostname: test.hostname, Confirmation: test.confirmation}},
			}
			if !cache.add(addr, "unwanted", 1, dns) {
				t.Fatal("untrusted reverse DNS prevented blacklisting")
			}
		})
	}
}

func TestDomainAllowlistFailsOpenOnUnavailableDNSResult(t *testing.T) {
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration:   config.Duration(time.Hour),
		MaxEntries:      10,
		DomainAllowlist: []string{"outlook.com"},
	}, nil)
	if !cache.add(netip.MustParseAddr("192.0.2.25"), "unwanted", 1, connectionDNSResult{status: message.ReverseDNSLookupFailed}) {
		t.Fatal("unavailable DNS evidence prevented blacklisting")
	}
}

func TestRejectedIPCachePromotesRepeatedAIRejections(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration:       config.Duration(time.Minute),
		RepeatThreshold:     3,
		RepeatWindow:        config.Duration(time.Hour),
		RepeatBlockDuration: config.Duration(24 * time.Hour),
		MaxEntries:          10,
		StateFile:           t.TempDir() + "/state.json",
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.40")
	for strike := 1; strike <= 3; strike++ {
		cache.add(addr, "unwanted", .99, connectionDNSResult{})
		entry, ok := cache.lookup(addr)
		if !ok {
			t.Fatalf("strike %d did not produce a block", strike)
		}
		wantLevel := rejectedIPBlockShort
		if strike == 3 {
			wantLevel = rejectedIPBlockRepeat
		}
		if entry.level != wantLevel || entry.strikeCount != strike {
			t.Fatalf("strike %d yielded level=%q count=%d", strike, entry.level, entry.strikeCount)
		}
		now = now.Add(2 * time.Minute)
	}
}

func TestRejectedIPCachePrunesStrikesOutsideWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration:       config.Duration(time.Minute),
		RepeatThreshold:     2,
		RepeatWindow:        config.Duration(10 * time.Minute),
		RepeatBlockDuration: config.Duration(time.Hour),
		MaxEntries:          10,
		StateFile:           t.TempDir() + "/state.json",
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.41")
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	now = now.Add(11 * time.Minute)
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	entry, ok := cache.lookup(addr)
	if !ok || entry.level != rejectedIPBlockShort || entry.strikeCount != 1 {
		t.Fatalf("old strike was not pruned: %+v, found=%v", entry, ok)
	}
}

func TestRejectedIPCacheRefreshesOnlyRepeatBlockWithoutAddingStrike(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration:          config.Duration(time.Minute),
		RepeatThreshold:        2,
		RepeatWindow:           config.Duration(2 * time.Hour),
		RepeatBlockDuration:    config.Duration(24 * time.Hour),
		RepeatRefreshOnAttempt: true,
		MaxEntries:             10,
		StateFile:              t.TempDir() + "/state.json",
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.42")
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	if record := cache.entries[addr]; record.ID == 0 {
		t.Fatal("IP reputation record was not assigned an ID")
	}
	now = now.Add(2 * time.Minute)
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	now = now.Add(time.Hour)
	entry, ok := cache.lookup(addr)
	if !ok || entry.strikeCount != 2 || !entry.expires.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("repeat refresh changed strikes or expiry incorrectly: %+v, found=%v", entry, ok)
	}
}

func TestRejectedIPCachePersistsReputation(t *testing.T) {
	stateFile := t.TempDir() + "/state.json"
	policy := config.IPReputationConfig{
		BlockDuration:       config.Duration(time.Minute),
		RepeatThreshold:     2,
		RepeatWindow:        config.Duration(time.Hour),
		RepeatBlockDuration: config.Duration(24 * time.Hour),
		MaxEntries:          10,
		StateFile:           stateFile,
	}
	now := time.Now().UTC().Truncate(time.Second)
	cache := newIPReputationStore(policy, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.43")
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	now = now.Add(2 * time.Minute)
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	state, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), `"classification"`) {
		t.Fatalf("persisted IP reputation contains redundant classification: %s", state)
	}

	reloaded := newIPReputationStore(policy, nil)
	if record := reloaded.entries[addr]; record.ID == 0 {
		t.Fatal("reloaded IP reputation record has no ID")
	}
	entry, ok := reloaded.lookup(addr)
	if !ok || entry.level != rejectedIPBlockRepeat || entry.strikeCount != 2 {
		t.Fatalf("persisted repeat reputation was not restored: %+v, found=%v", entry, ok)
	}
}

func TestRejectedIPCacheRepeatExpiryDiscardsStrikeHistory(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration:       config.Duration(time.Minute),
		RepeatThreshold:     2,
		RepeatWindow:        config.Duration(24 * time.Hour),
		RepeatBlockDuration: config.Duration(time.Hour),
		MaxEntries:          10,
		StateFile:           t.TempDir() + "/state.json",
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.44")
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	now = now.Add(2 * time.Minute)
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	now = now.Add(time.Hour)
	if _, ok := cache.lookup(addr); ok {
		t.Fatal("repeat block remained active at expiry")
	}
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	entry, _ := cache.lookup(addr)
	if entry.level != rejectedIPBlockShort || entry.strikeCount != 1 {
		t.Fatalf("expired repeat history was retained: %+v", entry)
	}
}

func TestRejectedIPCacheLegitimateMessagesRemoveOldestStrike(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration:       config.Duration(time.Minute),
		RepeatThreshold:     3,
		RepeatWindow:        config.Duration(24 * time.Hour),
		RepeatBlockDuration: config.Duration(24 * time.Hour),
		LegitimatePerStrike: 3,
		MaxEntries:          10,
		StateFile:           t.TempDir() + "/state.json",
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.45")
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	now = now.Add(2 * time.Minute)
	cache.lookup(addr) // expire the short block while retaining its strike
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	now = now.Add(2 * time.Minute)
	cache.lookup(addr)

	cache.recordLegitimate(addr)
	cache.recordLegitimate(addr)
	if got := cache.entries[addr]; got.LegitimateCount != 2 || len(got.Strikes) != 2 {
		t.Fatalf("credits before threshold = %d, strikes = %d", got.LegitimateCount, len(got.Strikes))
	}
	oldest := cache.entries[addr].Strikes[0]
	cache.recordLegitimate(addr)
	got := cache.entries[addr]
	if got.LegitimateCount != 0 || len(got.Strikes) != 1 || !got.Strikes[0].After(oldest) {
		t.Fatalf("legitimate threshold did not remove oldest strike: %+v", got)
	}
}

func TestRejectedIPCacheNewStrikeResetsLegitimateCredit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration:       config.Duration(time.Minute),
		RepeatThreshold:     3,
		RepeatWindow:        config.Duration(time.Hour),
		RepeatBlockDuration: config.Duration(time.Hour),
		LegitimatePerStrike: 3,
		MaxEntries:          10,
		StateFile:           t.TempDir() + "/state.json",
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.46")
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	now = now.Add(2 * time.Minute)
	cache.lookup(addr)
	cache.recordLegitimate(addr)
	cache.recordLegitimate(addr)
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	if got := cache.entries[addr]; got.LegitimateCount != 0 || len(got.Strikes) != 2 {
		t.Fatalf("new rejection did not reset credit: %+v", got)
	}
}

func TestRejectedIPCacheLegitimateDecayDoesNotCancelActiveBlock(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cache := newIPReputationStore(config.IPReputationConfig{
		BlockDuration:       config.Duration(time.Hour),
		RepeatThreshold:     3,
		RepeatWindow:        config.Duration(24 * time.Hour),
		RepeatBlockDuration: config.Duration(24 * time.Hour),
		LegitimatePerStrike: 1,
		MaxEntries:          10,
		StateFile:           t.TempDir() + "/state.json",
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.47")
	cache.add(addr, "unwanted", 1, connectionDNSResult{})
	cache.recordLegitimate(addr)
	entry, ok := cache.lookup(addr)
	if !ok || entry.level != rejectedIPBlockShort || entry.strikeCount != 0 {
		t.Fatalf("legitimate decay cancelled an active block: %+v, found=%v", entry, ok)
	}
}

func TestManualIPManagementListsOnlyActiveBlocks(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	stateFile := t.TempDir() + "/state.json"
	policy := config.IPReputationConfig{BlockDuration: config.Duration(time.Minute), RepeatThreshold: 3, RepeatWindow: config.Duration(time.Hour), RepeatBlockDuration: config.Duration(24 * time.Hour), MaxEntries: 10, StateFile: stateFile}
	cache := newIPReputationStore(policy, nil)
	cache.now = func() time.Time { return now }
	manual := netip.MustParseAddr("192.0.2.80")
	block, err := cache.manualAdd(manual)
	if err != nil || block.Level != rejectedIPBlockRepeat || !block.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("manual block = %+v, %v", block, err)
	}
	cache.add(netip.MustParseAddr("192.0.2.81"), "unwanted", 1, connectionDNSResult{})
	if got := cache.listActive(); len(got) != 2 {
		t.Fatalf("active blocks = %#v", got)
	}
	now = now.Add(2 * time.Minute)
	got := cache.listActive()
	if len(got) != 1 || got[0].IP != manual.String() {
		t.Fatalf("expired short block was listed: %#v", got)
	}
	removed, err := cache.manualDelete(manual)
	if err != nil || !removed || len(cache.listActive()) != 0 {
		t.Fatalf("manual delete = %v, %v", removed, err)
	}
	reloaded := newIPReputationStore(policy, nil)
	if len(reloaded.listActive()) != 0 {
		t.Fatal("manual deletion was not persisted")
	}
}

func TestActiveIPListAddsReverseDNSHostname(t *testing.T) {
	server := &Server{
		cfg:      config.Config{Milter: config.MilterConfig{ConnectionDNSTimeout: config.Duration(time.Second)}},
		resolver: &connectionTestResolver{ptr: []string{"dns.google."}},
	}
	entries := server.resolveActiveIPHostnames(context.Background(), []activeIPBlock{{IP: "8.8.8.8"}, {IP: "192.0.2.1"}})
	if entries[0].Hostname != "dns.google" {
		t.Fatalf("resolved hostname = %q", entries[0].Hostname)
	}
	if entries[1].Hostname != "" {
		t.Fatalf("non-routable hostname = %q", entries[1].Hostname)
	}
	formatted := formatActiveIPBlocks(entries, true)
	for _, want := range []string{"IP: 8.8.8.8 (dns.google)", "IP: 192.0.2.1 (not found)"} {
		if !strings.Contains(formatted, want) {
			t.Errorf("formatted list missing %q: %s", want, formatted)
		}
	}
	withoutLookup := formatActiveIPBlocks(entries, false)
	if strings.Contains(withoutLookup, "dns.google") || strings.Contains(withoutLookup, "not found") {
		t.Fatalf("ordinary IP list included DNS results: %s", withoutLookup)
	}
}
