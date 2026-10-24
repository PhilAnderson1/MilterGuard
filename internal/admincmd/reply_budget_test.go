package admincmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type budgetArchiveSource struct {
	data   map[uint64][]byte
	limits []int64
	loaded []uint64
}

func (s *budgetArchiveSource) ReadWithRecordID(id uint64, _ time.Time, limit int64) (ArchivedMessage, error) {
	s.limits = append(s.limits, limit)
	if int64(len(s.data[id])) > limit {
		return ArchivedMessage{}, ErrArchiveTooLarge
	}
	s.loaded = append(s.loaded, id)
	return ArchivedMessage{Contents: bytes.Clone(s.data[id])}, nil
}

func TestReplyBudgetBoundsArchiveReadsAcrossCommands(t *testing.T) {
	// Two 1000-byte attachments fit (2428 encoded/framing bytes each).
	// The final 1024 bytes cannot admit another archive, even before a read.
	source := &budgetArchiveSource{data: map[uint64][]byte{}}
	for _, id := range []uint64{1, 2, 3} {
		source.data[id] = bytes.Repeat([]byte("x"), 1000)
	}
	p := New(Dependencies{MessageSource: source, MaxMessageSize: 1 << 20})
	budget := NewReplyAttachmentBudget(2*2428 + 1024)
	ctx := WithReplyAttachmentBudget(context.Background(), budget)
	for _, id := range []uint64{1, 2, 3} {
		response := p.rejectionDetail(ctx, stores.Rejection{ID: id})
		want := 1
		if id == 3 {
			want = 0
		}
		if len(response.Attachments) != want {
			t.Fatalf("id %d: attachments=%d", id, len(response.Attachments))
		}
	}
	if len(source.loaded) != 2 || len(source.limits) != 2 || source.limits[1] >= source.limits[0] {
		t.Fatalf("reads were not cumulatively bounded: loaded=%v limits=%v", source.loaded, source.limits)
	}
	if !strings.Contains(budget.OmissionNotice(), "3") || !strings.Contains(budget.OmissionNotice(), "individually") {
		t.Fatalf("missing omission notice: %s", budget.OmissionNotice())
	}
	response := p.rejectionDetail(ctx, stores.Rejection{ID: 1})
	if len(source.limits) != 2 || len(response.Attachments) != 0 || !strings.Contains(response.Text, "already included") {
		t.Fatal("duplicate command reloaded its attachment")
	}
}

func TestReplyBudgetSkipsOversizedArchiveBeforeLoading(t *testing.T) {
	source := &budgetArchiveSource{data: map[uint64][]byte{
		1: bytes.Repeat([]byte("x"), 2000),
		2: bytes.Repeat([]byte("x"), 1000),
	}}
	p := New(Dependencies{MessageSource: source, MaxMessageSize: 1 << 20})
	budget := NewReplyAttachmentBudget(2428)
	ctx := WithReplyAttachmentBudget(context.Background(), budget)
	first := p.rejectionDetail(ctx, stores.Rejection{ID: 1})
	second := p.rejectionDetail(ctx, stores.Rejection{ID: 2})
	if len(first.Attachments) != 0 || len(second.Attachments) != 1 || len(source.loaded) != 1 || source.loaded[0] != 2 {
		t.Fatalf("oversized archive was loaded or consumed the budget: loaded=%v", source.loaded)
	}
	if !strings.Contains(budget.OmissionNotice(), "1") {
		t.Fatal("omitted ID not reported")
	}
}
