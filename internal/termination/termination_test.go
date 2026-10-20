package termination

import "testing"

func TestUnwind(t *testing.T) {
	for _, code := range []Code{CPUExceeded, MemoryExceeded, Cancelled} {
		var failure Failure
		var cleaned, continued int
		func() {
			defer Recover(&failure)
			defer func() { cleaned++ }()
			func() {
				defer func() { cleaned++ }()
				func() {
					defer func() { cleaned++ }()
					Fail(Failure{Code: code, Limit: 123})
					continued++
				}()
				continued++
			}()
			continued++
		}()
		if failure != (Failure{Code: code, Limit: 123}) || cleaned != 3 || continued != 0 {
			t.Fatalf("failure=%+v cleanup=%d continued=%d", failure, cleaned, continued)
		}
	}
}

func TestUnrelatedPanicPassesThrough(t *testing.T) {
	fault := &struct{}{}
	defer func() {
		if got := recover(); got != fault {
			t.Fatalf("panic=%v, want original fault", got)
		}
	}()
	var failure Failure
	func() {
		defer Recover(&failure)
		panic(fault)
	}()
	t.Fatal("fault swallowed")
}

func TestCatchAllRethrowsTermination(t *testing.T) {
	var failure Failure
	converted := false
	func() {
		defer Recover(&failure)
		defer func() {
			if value := recover(); value != nil {
				Rethrow(value)
				converted = true
			}
		}()
		Fail(Failure{Code: Cancelled})
	}()
	if converted || failure.Code != Cancelled {
		t.Fatalf("converted=%v failure=%+v", converted, failure)
	}
	Rethrow("ordinary legacy error")
}

func TestInvalidCodeIsProgrammingPanic(t *testing.T) {
	for _, code := range []Code{None, Code(255)} {
		func() {
			defer func() {
				if value := recover(); value != "termination: invalid failure code" {
					t.Fatalf("invalid code %d panic=%v", code, value)
				}
			}()
			var failure Failure
			defer Recover(&failure)
			Fail(Failure{Code: code})
		}()
	}
}

func BenchmarkFailureUnwind(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		var failure Failure
		func() {
			defer Recover(&failure)
			func() {
				Fail(Failure{Code: MemoryExceeded, Limit: 64 << 20})
			}()
		}()
		if failure.Code != MemoryExceeded {
			b.Fatal("lost failure")
		}
	}
}
