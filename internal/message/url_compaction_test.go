package message

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestURLCompactionCompatibility(t *testing.T) {
	for _, test := range []struct{ name, input, want string }{
		{"unchanged", "HTTP://u:p@example.com/a?x=1#b", "HTTP://u:p@example.com/a?x=1#b"},
		{"path", "https://e.com/" + strings.Repeat("a", 80) + "/b", "https://e.com/" + strings.Repeat("a", 64) + "/b"},
		{"filename", "https://e.com/" + strings.Repeat("a", 80) + "%2Epdf", "https://e.com/" + strings.Repeat("a", 58) + "%2Epdf"},
		{"query", "https://e.com/?" + strings.Repeat("k", 60) + "=" + strings.Repeat("é", 60) + "&x=y", "https://e.com/?" + strings.Repeat("k", 50) + "=" + strings.Repeat("é", 50) + "&x=y"},
		{"userinfo", "HTTP://u:p@e.com/?x=" + strings.Repeat("a", 60), "http://[userinfo-omitted]@e.com/?x=" + strings.Repeat("a", 50)},
		{"fragment", "https://e.com/#" + strings.Repeat("%20", 30), "https://e.com/#" + strings.Repeat("%20", 16) + "%2"},
		{"invalid-url", "%" + strings.Repeat("😀", 600), "%" + strings.Repeat("😀", 511)},
		{"invalid-utf8", "https://e.com/?x=" + strings.Repeat("\xff", 60), "https://e.com/?x=" + strings.Repeat("�", 50)},
		{"empty-query", "https://e.com/?", "https://e.com/?"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := promptURL(test.input, true); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
			if got := promptURL(test.input, false); got != test.input {
				t.Fatal("disabled compaction changed URL")
			}
		})
	}
}

func TestURLCompactionGuards(t *testing.T) {
	input := "https://e.com/?" + strings.Repeat("&a", 10000)
	t.Run("memory", func(t *testing.T) {
		memory := resourceguard.NewMemory(1)
		if got, ok := promptURLWithBudget(input, true, memory, nil); ok || got != "" || !memory.Exhausted() {
			t.Fatal("allocation limit was ignored")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		calls := 0
		stop := func() bool { calls++; return calls >= 3 }
		if got, ok := promptURLWithBudget("https://e.com/"+strings.Repeat("a", 10000), true, nil, stop); ok || got != "" {
			t.Fatal("cancellation during component scan was ignored")
		}
	})
	t.Run("accounting", func(t *testing.T) {
		memory := resourceguard.NewMemory(1 << 20)
		got, ok := promptURLWithBudget(input, true, memory, nil)
		if !ok || len(got) != 512 || memory.Used() < int64(len(got)) {
			t.Fatalf("result length=%d, ok=%v, charged=%d", len(got), ok, memory.Used())
		}
	})
}

func TestURLCompactionScratchIsBounded(t *testing.T) {
	// A large separator count must not allocate one slice entry per separator.
	input := "https://e.com/?" + strings.Repeat("&a", 200000)
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			promptURL(input, true)
		}
	})
	if result.AllocedBytesPerOp() > 16<<10 {
		t.Fatalf("compaction allocated %d bytes per call", result.AllocedBytesPerOp())
	}
}

func TestPlainURLCompactionCancellationIsIncomplete(t *testing.T) {
	input := "https://e.com/" + strings.Repeat("a", 10000)
	for _, collect := range []bool{false, true} {
		calls := 0
		stop := func() bool { calls++; return calls >= 3 }
		var links *linkCollector
		if collect {
			links = &linkCollector{compactURLs: true, shouldStop: stop}
		}
		got, complete := rewritePlainTextURLs(input, true, links, stop)
		if complete || got != input {
			t.Fatalf("collect=%v: cancelled rewrite returned complete=%v, text=%q", collect, complete, got)
		}
	}
}
