package cascadia

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"testing"
)

func expectTermination(t *testing.T, code termination.Code, work func()) {
	t.Helper()
	var failure termination.Failure
	func() { defer termination.Recover(&failure); work(); t.Fatal("resource failure returned normally") }()
	if failure.Code != code {
		t.Fatalf("failure=%+v want %v", failure, code)
	}
}
