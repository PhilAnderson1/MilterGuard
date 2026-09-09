package milter

import (
	"bytes"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/jsonstore"
)

func TestFeatureStoresReportFlushStatistics(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	directory := t.TempDir()
	ip := newIPReputationStore(config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 10, StateFile: filepath.Join(directory, "ip.json")}, logger)
	contacts := newCorrespondentStore(config.CorrespondentsConfig{LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all", File: filepath.Join(directory, "contacts.json"), MaxEntries: 10}, logger)
	rejections := newRejectionHistoryStore(config.RejectionHistoryConfig{File: filepath.Join(directory, "rejections.json"), Expiry: config.Duration(time.Hour), MaxEntries: 10}, logger)
	domains := newDomainRegistrationStore(config.DomainRegistrationConfig{Enabled: true, Timeout: config.Duration(time.Second), MaxEntries: 10, StateFile: filepath.Join(directory, "domains.json")}, logger)
	manager := jsonstore.NewManager(logger)
	manager.Add(ip.db, contacts.db, rejections.db, domains.db)
	manager.SetDeferred(true)
	address := netip.MustParseAddr("192.0.2.10")
	ip.add(address, 1, connectionDNSResult{})
	ip.lookup(address)
	if err := contacts.learn("local@example.com", []string{"friend@example.net"}); err != nil {
		t.Fatal(err)
	}
	contacts.match("friend@example.net", []string{"local@example.com"})
	if err := rejections.add("sender@example.net", "", "Test subject", []string{"local@example.com"}, []string{"test"}); err != nil {
		t.Fatal(err)
	}
	rejections.list("local@example.com")
	if err := domains.db.Put(domainRegistrationRecord{Domain: "example.com", RegisteredAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	domains.db.Get("example.com")
	manager.Flush("timer")
	logged := output.String()
	for _, want := range []string{"IP: r 1, w 1, d 0, f yes", "Contacts: r 1, w 1, d 0, f yes", "Rejections: r 1, w 1, d 0, f yes", "Domains: r 1, w 1, d 0, f yes"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("flush log missing %q: %s", want, logged)
		}
	}
}
