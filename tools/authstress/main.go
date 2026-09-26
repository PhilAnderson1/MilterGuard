// Command authstress exercises exact-message storage at configured connection
// and message-size limits without sending mail or performing DNS lookups.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

type measurement struct {
	Storage           string `json:"storage"`
	Connections       int    `json:"connections"`
	MessageBytes      int64  `json:"message_bytes"`
	LogicalTotalBytes int64  `json:"logical_total_bytes"`
	FillDurationMS    int64  `json:"fill_duration_ms"`
	CloseDurationMS   int64  `json:"close_duration_ms"`
	HeapBefore        uint64 `json:"heap_before"`
	HeapFilled        uint64 `json:"heap_filled"`
	HeapAfterClose    uint64 `json:"heap_after_close"`
	HeapSystemFilled  uint64 `json:"heap_system_filled"`
	FDsBefore         int    `json:"fds_before"`
	FDsFilled         int    `json:"fds_filled"`
	FDsAfterClose     int    `json:"fds_after_close"`
}

func main() {
	storage := flag.String("message-storage", "memory", "exact-message storage: memory or file")
	connections := flag.Int("connections", 64, "simultaneous exact-message stores")
	messageBytes := flag.Int64("message-bytes", 10<<20, "bytes retained per store")
	flag.Parse()
	if *storage != "memory" && *storage != "file" {
		fatalf("invalid -message-storage: must be memory or file")
	}
	if *connections < 1 || *messageBytes < 1 {
		fatalf("connections and message-bytes must be positive")
	}
	if *messageBytes > int64(maxInt()) {
		fatalf("message-bytes exceeds platform allocation limit")
	}
	if int64(*connections) > int64(^uint64(0)>>1) / *messageBytes {
		fatalf("logical total byte count overflows int64")
	}

	payload := make([]byte, int(*messageBytes))
	for index := range payload {
		payload[index] = byte(index*31 + 17)
	}
	runtime.GC()
	before := memoryStats()
	result := measurement{
		Storage: *storage, Connections: *connections, MessageBytes: *messageBytes,
		LogicalTotalBytes: int64(*connections) * *messageBytes,
		HeapBefore:        before.HeapAlloc, FDsBefore: openFDs(),
	}

	stores := make([]mailauth.ExactMessage, 0, *connections)
	closeStores := func() error {
		var first error
		for _, store := range stores {
			if err := store.Close(); err != nil && first == nil {
				first = err
			}
		}
		stores = nil
		return first
	}
	defer closeStores()
	started := time.Now()
	for range *connections {
		store, err := mailauth.NewExactMessage(*storage, *messageBytes)
		if err != nil {
			fatalf("create exact-message store: %v", err)
		}
		stores = append(stores, store)
		if err := store.AddBody(payload); err != nil {
			fatalf("fill exact-message store: %v", err)
		}
		reader, size, err := store.ReaderAt()
		if err != nil || size != *messageBytes {
			fatalf("read exact-message store: size=%d error=%v", size, err)
		}
		var final [1]byte
		if n, err := reader.ReadAt(final[:], size-1); n != 1 || err != nil && err != io.EOF || final[0] != payload[len(payload)-1] {
			fatalf("verify exact-message store final byte: n=%d byte=%d error=%v", n, final[0], err)
		}
	}
	result.FillDurationMS = time.Since(started).Milliseconds()
	filled := memoryStats()
	result.HeapFilled = filled.HeapAlloc
	result.HeapSystemFilled = filled.HeapSys
	result.FDsFilled = openFDs()

	started = time.Now()
	if err := closeStores(); err != nil {
		fatalf("close exact-message stores: %v", err)
	}
	result.CloseDurationMS = time.Since(started).Milliseconds()
	runtime.GC()
	after := memoryStats()
	result.HeapAfterClose = after.HeapAlloc
	result.FDsAfterClose = openFDs()
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fatalf("write result: %v", err)
	}
}

func memoryStats() runtime.MemStats {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats
}

func openFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

func maxInt() int { return int(^uint(0) >> 1) }

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
