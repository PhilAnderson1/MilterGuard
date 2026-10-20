package html

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

type terminatingReader struct{}

func (terminatingReader) Read([]byte) (int, error) {
	termination.Fail(termination.Failure{Code: termination.Cancelled})
	return 0, nil
}

func TestStageTerminationPassesThroughHTMLRecovery(t *testing.T) {
	for name, work := range map[string]func(){
		"parser catch-all": func() { Parse(terminatingReader{}) },
		"fragment":         func() { ParseFragment(terminatingReader{}, nil) },
		"tokenizer": func() {
			z := NewTokenizerWithLimits(terminatingReader{}, ResourceLimits{})
			z.Next()
		},
		"required allocation": func() {
			ParseWithOptions(strings.NewReader("<p>text</p>"), ParseOptionResourceLimits(ResourceLimits{Memory: resourceguard.NewMemory(1)}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			var failure termination.Failure
			func() {
				defer termination.Recover(&failure)
				work()
				t.Fatal("stage termination was swallowed")
			}()
			want := termination.Cancelled
			if name == "required allocation" {
				want = termination.MemoryExceeded
			}
			if failure.Code != want {
				t.Fatalf("failure=%+v want %v", failure, want)
			}
		})
	}
}

func expectTermination(t *testing.T, code termination.Code, work func()) {
	t.Helper()
	var failure termination.Failure
	func() { defer termination.Recover(&failure); work(); t.Fatal("resource failure returned normally") }()
	if failure.Code != code {
		t.Fatalf("failure=%+v want %v", failure, code)
	}
}

type panickingReader struct{ value any }

func (r panickingReader) Read([]byte) (int, error) { panic(r.value) }

func TestUnexpectedParserPanicsRemainVisible(t *testing.T) {
	marker := &struct{ message string }{"unexpected failure"}
	for name, work := range map[string]func(){
		"reader":          func() { Parse(panickingReader{marker}) },
		"fragment reader": func() { ParseFragment(panickingReader{marker}, nil) },
		"checkpoint": func() {
			calls := 0
			ParseWithOptions(strings.NewReader(strings.Repeat("<p>text</p>", 300)), ParseOptionResourceLimits(ResourceLimits{ShouldStop: func() {
				calls++
				if calls == 2 {
					panic(marker)
				}
			}}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if got := recover(); got != marker {
					t.Fatalf("panic=%v, want original marker", got)
				}
			}()
			work()
			t.Fatal("unexpected panic was converted to a parse error")
		})
	}
}
