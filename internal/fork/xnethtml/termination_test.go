package html

import (
	"errors"
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

func TestUnexpectedParserPanicsBecomeParseFailures(t *testing.T) {
	marker := &struct{ message string }{"unexpected failure"}
	for name, work := range map[string]func() error{
		"reader":          func() error { _, err := Parse(panickingReader{marker}); return err },
		"fragment reader": func() error { _, err := ParseFragment(panickingReader{marker}, nil); return err },
		"checkpoint": func() error {
			calls := 0
			_, err := ParseWithOptions(strings.NewReader(strings.Repeat("<p>text</p>", 300)), ParseOptionResourceLimits(ResourceLimits{ShouldStop: func() {
				calls++
				if calls == 2 {
					panic(marker)
				}
			}}))
			return err
		},
		"option": func() error {
			_, err := ParseWithOptions(strings.NewReader("<p>text</p>"), func(*parseConfig) { panic(marker) })
			return err
		},
		"fragment option": func() error {
			_, err := ParseFragmentWithOptions(strings.NewReader("text"), nil, func(*parseConfig) { panic(marker) })
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := work(); !errors.Is(err, ErrParserPanic) {
				t.Fatalf("error=%v, want ErrParserPanic", err)
			}
		})
	}
}
