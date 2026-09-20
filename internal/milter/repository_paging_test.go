package milter

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func TestRepositoryListPagesApplyCallerLimit(t *testing.T) {
	ctx := context.Background()

	correspondents := newTestCorrespondentStore(t, config.CorrespondentsConfig{
		UseAllowlist: true, Scope: "per_sender", MaxEntries: 10, LegitimateSenderMinMessages: 1,
	}, nil)
	for _, sender := range []string{"one@example.net", "two@example.net"} {
		if _, err := correspondents.AddManual(ctx, sender, "owner@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	correspondentPage, err := correspondents.ListCorrespondents(ctx, stores.CorrespondentListQuery{
		Recipients: stores.RecipientScope{All: true}, Limit: 1,
	})
	if err != nil || len(correspondentPage.Entries) != 1 || !correspondentPage.Truncated {
		t.Fatalf("correspondent page = %+v, error = %v", correspondentPage, err)
	}

	rejections, _ := newTestRejectionHistoryStore(t, config.RejectionHistoryConfig{
		Expiry: config.Duration(24 * time.Hour), MaxEntries: 10,
	})
	for _, sender := range []string{"one@example.net", "two@example.net"} {
		if _, err := rejections.AddRejection(ctx, stores.NewRejection{
			VisibleSender: sender, Recipients: []string{"owner@example.com"}, Reasons: []string{"test"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	rejectionPage, err := rejections.ListRejections(ctx, stores.RejectionListQuery{
		Recipients: stores.RecipientScope{All: true}, Limit: 1,
	})
	if err != nil || len(rejectionPage.Entries) != 1 || !rejectionPage.Truncated {
		t.Fatalf("rejection page = %+v, error = %v", rejectionPage, err)
	}

	ipReputation := newTestIPReputationStore(t, config.IPReputationConfig{
		BlockDuration: config.Duration(time.Hour), MaxEntries: 10,
	}, nil)
	for _, address := range []string{"192.0.2.1", "192.0.2.2"} {
		if _, err := ipReputation.AddManualBlock(ctx, netip.MustParseAddr(address)); err != nil {
			t.Fatal(err)
		}
	}
	ipPage, err := ipReputation.ListActiveBlocks(ctx, stores.IPBlockListQuery{Limit: 1})
	if err != nil || len(ipPage.Entries) != 1 || !ipPage.Truncated {
		t.Fatalf("IP block page = %+v, error = %v", ipPage, err)
	}
}
