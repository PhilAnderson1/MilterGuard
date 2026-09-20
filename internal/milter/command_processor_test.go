package milter

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

func commandProcessorTestConfig(path string) config.Config {
	return config.Config{
		Persistence: config.PersistenceConfig{DatabaseFile: path},
		Correspondents: config.CorrespondentsConfig{
			UseAllowlist: true, Scope: "per_sender", MaxEntries: 1000,
			LegitimateSenderMinMessages: 3,
		},
		IPReputation: config.IPReputationConfig{
			BlockDuration: config.Duration(time.Hour), MaxEntries: 1000,
		},
		RejectionHistory: config.RejectionHistoryConfig{
			Expiry: config.Duration(30 * 24 * time.Hour), MaxEntries: 1000,
		},
	}
}

func TestCommandProcessorUsesAdministratorDefaults(t *testing.T) {
	cfg := commandProcessorTestConfig(filepath.Join(t.TempDir(), "milterguard.db"))
	processor, closeProcessor, err := OpenCommandProcessor(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeProcessor()
	actor := admincmd.Actor{Administrator: true, DefaultRecipient: "*"}

	if _, err := processor.ExecuteLine(context.Background(), "WHITELIST ADD news@example.net", actor); err == nil {
		t.Fatal("WHITELIST ADD without an explicit recipient succeeded")
	}
	response, err := processor.ExecuteLine(context.Background(), "WHITELIST ADD news@example.net owner@example.com", actor)
	if err != nil || !strings.Contains(response.Text, "allowlist entry added") {
		t.Fatalf("add response=%#v err=%v", response, err)
	}
	response, err = processor.ExecuteLine(context.Background(), "WHITELIST LIST all", actor)
	if err != nil || !strings.Contains(response.Text, "news@example.net") || !strings.Contains(response.Text, "owner@example.com") {
		t.Fatalf("list response=%#v err=%v", response, err)
	}
}

func TestCommandProcessorListOrderFollowsActorPreference(t *testing.T) {
	cfg := commandProcessorTestConfig(filepath.Join(t.TempDir(), "milterguard.db"))
	processor, closeProcessor, err := OpenCommandProcessor(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeProcessor()
	admin := admincmd.Actor{Administrator: true, DefaultRecipient: "*"}
	for _, sender := range []string{"older@example.net", "newer@example.net"} {
		if _, err := processor.ExecuteLine(context.Background(), "WHITELIST ADD "+sender+" owner@example.com", admin); err != nil {
			t.Fatal(err)
		}
	}

	newestFirst, err := processor.ExecuteLine(context.Background(), "WHITELIST LIST * all", admin)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(newestFirst.Text, "newer@example.net") > strings.Index(newestFirst.Text, "older@example.net") {
		t.Fatalf("email-style list is not newest-first:\n%s", newestFirst.Text)
	}

	admin.NewestLast = true
	newestLast, err := processor.ExecuteLine(context.Background(), "WHITELIST LIST * all", admin)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(newestLast.Text, "older@example.net") > strings.Index(newestLast.Text, "newer@example.net") {
		t.Fatalf("terminal-style list is not oldest-first:\n%s", newestLast.Text)
	}
}

func TestCommandProcessorsCanWriteSameLiveDatabase(t *testing.T) {
	cfg := commandProcessorTestConfig(filepath.Join(t.TempDir(), "milterguard.db"))
	first, closeFirst, err := OpenCommandProcessor(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFirst()
	second, closeSecond, err := OpenCommandProcessor(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSecond()

	actor := admincmd.Actor{Administrator: true, DefaultRecipient: "*"}
	processors := []*admincmd.Processor{first, second}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for index := range 20 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			line := fmt.Sprintf("WHITELIST ADD sender%d@example.net owner@example.com", index)
			_, err := processors[index%len(processors)].ExecuteLine(context.Background(), line, actor)
			errs <- err
		}(index)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	response, err := first.ExecuteLine(context.Background(), "WHITELIST LIST * all", actor)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 20 {
		if !strings.Contains(response.Text, fmt.Sprintf("sender%d@example.net", index)) {
			t.Fatalf("concurrent entry %d is missing", index)
		}
	}
}

func TestCommandProcessorHonorsCanceledContext(t *testing.T) {
	cfg := commandProcessorTestConfig(filepath.Join(t.TempDir(), "milterguard.db"))
	processor, closeProcessor, err := OpenCommandProcessor(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeProcessor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = processor.ExecuteLine(ctx, "WHITELIST LIST * all", admincmd.Actor{Administrator: true, DefaultRecipient: "*"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}
