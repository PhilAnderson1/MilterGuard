package sqlite

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

type rowScanner interface{ Scan(...any) error }

func unixMillis(value time.Time) int64     { return value.UTC().UnixMilli() }
func timeFromMillis(value int64) time.Time { return time.UnixMilli(value).UTC() }

func placeholders(count int) string { return strings.TrimSuffix(strings.Repeat("?,", count), ",") }

func valuePlaceholders(rows, columns int) string {
	return strings.TrimSuffix(strings.Repeat("("+placeholders(columns)+"),", rows), ",")
}

func normalizedAddressSet(values []string, maximum int) map[string]bool {
	result := make(map[string]bool)
	for _, value := range values {
		if len(result) >= maximum {
			break
		}
		if value = message.NormalizeEmailAddress(value); value != "" {
			result[value] = true
		}
	}
	return result
}

func sortedSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canonicalIP(addr netip.Addr) netip.Addr {
	if addr.Is6() {
		addr = addr.WithZone("")
	}
	return addr.Unmap()
}
