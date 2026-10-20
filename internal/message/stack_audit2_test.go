package message

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestMIMEReplayRestoresPartCount(t *testing.T) {
	const parts = 255
	var body strings.Builder
	for i := 0; i < parts; i++ {
		fmt.Fprintf(&body, "--x\r\nContent-Type: text/plain\r\n\r\npart-%03d\r\n", i)
	}
	body.WriteString("--x--\r\n")
	data := []byte(body.String())
	// Vary the primary cutoff to exercise failures both inside individual part
	// boundaries and in the outer multipart bookkeeping. Fallback has room to finish.
	for limit := int64(1024); limit <= 100<<10; limit += 1024 {
		b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 4 << 20})
		b.primaryMemory = resourceguard.NewMemory(limit)
		result := extractMIMEWithBudget("multipart/alternative; boundary=x", "", "", data, 0, b)
		if result.incomplete() || result.Text != "part-254" || b.parts != parts {
			t.Fatalf("primary limit=%d parts=%d text=%q incomplete=%v terminal=%+v", limit, b.parts, result.Text, result.incomplete(), b.terminal)
		}
	}
}
