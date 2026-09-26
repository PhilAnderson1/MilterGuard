//go:build ignore

// Usage: go run verify.go MESSAGE.eml
package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: verify MESSAGE.eml")
	}
	message, err := os.ReadFile(os.Args[1])
	check(err)
	record, err := os.ReadFile("dkim-record.txt")
	check(err)
	resolver := dns.MockResolver{TXT: map[string][]string{"probe._domainkey.example.test.": {strings.TrimSpace(string(record))}}}
	results, err := dkim.Verify(context.Background(), slog.New(slog.DiscardHandler), resolver, false, dkim.DefaultPolicy, bytes.NewReader(message), true)
	check(err)
	for i, result := range results {
		fmt.Printf("signature %d: %s", i+1, result.Status)
		if result.Err != nil {
			fmt.Printf(" (%v)", result.Err)
		}
		fmt.Println()
	}
	if len(results) == 0 {
		panic("no DKIM signatures")
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
