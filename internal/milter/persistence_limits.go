package milter

import "math"

const persistentStoreReadMargin int64 = 10

func persistentStoreReadLimit(maxEntries int, estimatedEntryBytes int64) int64 {
	bytesPerConfiguredEntry := estimatedEntryBytes * persistentStoreReadMargin
	if maxEntries <= 0 {
		return bytesPerConfiguredEntry
	}
	if int64(maxEntries) > math.MaxInt64/bytesPerConfiguredEntry {
		return math.MaxInt64
	}
	return int64(maxEntries) * bytesPerConfiguredEntry
}
