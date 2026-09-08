package milter

import (
	"math"
	"testing"
)

func TestPersistentStoreReadLimitsScaleWithConfiguredEntries(t *testing.T) {
	const maxEntries = 10000
	tests := []struct {
		name      string
		estimated int64
	}{
		{name: "correspondents", estimated: estimatedCorrespondentEntryBytes},
		{name: "IP reputation", estimated: estimatedIPReputationEntryBytes},
		{name: "rejection history", estimated: maximumRejectionHistoryEntryBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := int64(maxEntries) * test.estimated * persistentStoreReadMargin
			if got := persistentStoreReadLimit(maxEntries, test.estimated); got != want {
				t.Fatalf("read limit = %d, want %d", got, want)
			}
		})
	}
}

func TestPersistentStoreReadLimitHandlesOverflow(t *testing.T) {
	if got := persistentStoreReadLimit(math.MaxInt, 1<<20); got != math.MaxInt64 {
		t.Fatalf("overflow limit = %d, want %d", got, int64(math.MaxInt64))
	}
}
