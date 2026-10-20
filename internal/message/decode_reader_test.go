package message

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodersPreserveRecoveryWithStopChecks(t *testing.T) {
	for _, tc := range []struct{ encoding, input string }{
		{"base64", "aGVsbG8="}, {"base64", "aGVsbG8"}, {"base64", "aGVsbG8=!!!"}, {"base64", "!"},
		{"quoted-printable", "hello=20world=\r\nnext"}, {"quoted-printable", "hello=XX"}, {"binary", "hello"}, {"unknown", "hello"},
	} {
		want, bad := decodeTransferRecovering(tc.encoding, []byte(tc.input))
		got, incomplete := decodeTransferRecoveringWithStop(tc.encoding, []byte(tc.input), func() { return })
		if !bytes.Equal(got, want) || bad != incomplete {
			t.Fatalf("%s: recovery changed", tc.encoding)
		}
	}
	for _, label := range []string{"", "utf-8", "windows-1252", "big5", "iso-2022-jp", "unknown"} {
		for _, input := range [][]byte{[]byte("hello"), {0xff, 0x92, 'a'}, []byte("\xef\xbb\xbfhello")} {
			want, complete := decodeCharset(label, input, 100)
			got, ok := decodeCharsetWithStop(label, input, 100, func() { return })
			if got != want || ok != complete {
				t.Fatalf("%s: text charset recovery changed", label)
			}

			if got := decodeHTMLCharsetWithStop(label, input, 100, func() { return }); got != decodeHTMLCharset(label, input, 100) {
				t.Fatalf("%s: HTML charset recovery changed", label)
			}

		}
	}
}

func TestDecodersStopWithoutRecoveryRetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(func()) bool
	}{
		{"base64", func(stop func()) bool {
			out, _ := decodeTransferRecoveringWithStop("base64", []byte(strings.Repeat("YWFh", 100000)), stop)
			return len(out) == 0
		}},
		{"base64-no-output", func(stop func()) bool {
			out, _ := decodeTransferRecoveringWithStop("base64", []byte(strings.Repeat("\r\n", 100000)), stop)
			return len(out) == 0
		}},
		{"quoted-printable-no-output", func(stop func()) bool {
			out, _ := decodeTransferRecoveringWithStop("quoted-printable", []byte(strings.Repeat("=\r\n", 100000)), stop)
			return len(out) == 0
		}},
		{"text-charset", func(stop func()) bool {
			out, ok := decodeCharsetWithStop("windows-1252", bytes.Repeat([]byte{0x92}, 100000), 1<<20, stop)
			return out == "" && !ok
		}},
		{"html-charset", func(stop func()) bool {
			return decodeHTMLCharsetWithStop("big5", bytes.Repeat([]byte{0xa4, 0x40}, 100000), 1<<20, stop) == ""
		}},
		{"html-detection", func(stop func()) bool {
			return decodeHTMLCharsetWithStop("", bytes.Repeat([]byte{0x92}, 100000), 1<<20, stop) == ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			stop := func() {
				calls++
				if calls >= 4 {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}

				return
			}
			expectTermination(t, termination.CPUExceeded, func() { tc.run(stop) })
			if calls != 4 {
				t.Fatalf("calls=%d", calls)
			}
		})
	}
}

func TestMIMEDecodingCPUFailureIsReported(t *testing.T) {
	calls := 0
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{BeginFallback: func() bool { return false }, CheckPrimary: func() {
		calls++
		if calls >= 4 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}

		return
	}})
	got := extractMIMEWithBudget("text/html", "base64", "", []byte(strings.Repeat("YWFh", 100000)), 0, budget)
	if !got.ExtractionIncomplete || !got.HTMLCPULimitExceeded {
		t.Fatalf("cancelled decoding not reported: %+v", got)
	}
}
