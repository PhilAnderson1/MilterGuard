package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
)

type rowScanner interface{ Scan(...any) error }

func capacityExcessTx(ctx context.Context, tx *sql.Tx, table string, maximum int) (int, error) {
	var excess int
	query := fmt.Sprintf(`SELECT max(count(*) - ?, 0) FROM %s`, table)
	err := tx.QueryRowContext(ctx, query, maximum).Scan(&excess)
	return excess, err
}

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
		if value = mailaddr.Normalize(value); value != "" {
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
