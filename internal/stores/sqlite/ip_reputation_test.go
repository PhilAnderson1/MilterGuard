package sqlite

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func testIPRepository(t *testing.T, options IPReputationOptions) *ipReputationRepository {
	t.Helper()
	db, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewIPReputation(db, options, nil).(*ipReputationRepository)
}

func TestIPRepositoryPromotesAndRefreshesRepeatBlock(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	repository := testIPRepository(t, IPReputationOptions{
		BlockDuration: time.Hour, RepeatThreshold: 2, RepeatWindow: 24 * time.Hour,
		RepeatBlockDuration: 30 * 24 * time.Hour, RepeatRefreshOnAttempt: true,
		MaxEntries: 10, Now: func() time.Time { return now },
	})
	addr := netip.MustParseAddr("192.0.2.10")
	first, err := repository.RecordRejection(context.Background(), addr)
	if err != nil || first.Level != stores.IPBlockLevelShort || first.StrikeCount != 1 {
		t.Fatalf("first block = %+v, err=%v", first, err)
	}
	now = now.Add(2 * time.Hour)
	second, err := repository.RecordRejection(context.Background(), addr)
	if err != nil || second.Level != stores.IPBlockLevelRepeat || second.StrikeCount != 2 {
		t.Fatalf("second block = %+v, err=%v", second, err)
	}
	previousExpiry := second.ExpiresAt
	now = now.Add(2 * time.Minute)
	refreshed, found, err := repository.ActiveBlock(context.Background(), addr)
	if err != nil || !found || !refreshed.ExpiresAt.After(previousExpiry) || refreshed.StrikeCount != 2 {
		t.Fatalf("refreshed block = %+v, found=%v, err=%v", refreshed, found, err)
	}
}

func TestIPRepositoryCanonicalizesAddressesAndDecaysStrikes(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	repository := testIPRepository(t, IPReputationOptions{
		BlockDuration: time.Minute, RepeatThreshold: 3, RepeatWindow: time.Hour,
		RepeatBlockDuration: 24 * time.Hour, LegitimatePerStrike: 2,
		MaxEntries: 10, Now: func() time.Time { return now },
	})
	zoned := netip.MustParseAddr("fe80::1%submission")
	if _, err := repository.RecordRejection(context.Background(), zoned); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if err := repository.RecordLegitimate(context.Background(), zoned.WithZone("other")); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordLegitimate(context.Background(), zoned.WithZone("third")); err != nil {
		t.Fatal(err)
	}
	count, err := repository.Count(context.Background())
	if err != nil || count != 0 {
		t.Fatalf("record count = %d, want 0, err=%v", count, err)
	}
}

func TestIPRepositoryManualOperationsAndCleanup(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	repository := testIPRepository(t, IPReputationOptions{
		BlockDuration: time.Hour, RepeatThreshold: 2, RepeatWindow: time.Hour,
		RepeatBlockDuration: 24 * time.Hour, MaxEntries: 10, Now: func() time.Time { return now },
	})
	addr := netip.MustParseAddr("192.0.2.20")
	if block, err := repository.AddManualBlock(context.Background(), addr); err != nil || block.Level != stores.IPBlockLevelRepeat {
		t.Fatalf("manual block = %+v, err=%v", block, err)
	}
	page, err := repository.ListActiveBlocks(context.Background(), stores.IPBlockListQuery{Limit: 10})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Address != addr {
		t.Fatalf("active blocks = %+v, err=%v", page, err)
	}
	deleted, err := repository.Delete(context.Background(), addr)
	if err != nil || !deleted {
		t.Fatalf("delete = %v, err=%v", deleted, err)
	}
}
