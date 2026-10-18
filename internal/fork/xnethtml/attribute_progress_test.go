package html

import (
	"fmt"
	"strings"
	"testing"
)

func TestAttributeProcessingCancellation(t *testing.T) {
	for _, materialize := range []bool{false, true} {
		for _, longValue := range []bool{false, true} {
			t.Run(fmt.Sprintf("token=%v/long=%v", materialize, longValue), func(t *testing.T) {
				count, width := 1024, 1000
				if longValue {
					count, width = 1, 8192
				}
				var source strings.Builder
				source.WriteString("<div")
				for i := 0; i < count; i++ {
					fmt.Fprintf(&source, " a%d='%s'", i, strings.Repeat("x", width))
				}
				source.WriteString(">")
				armed, calls := false, 0
				z := NewTokenizerWithStop(strings.NewReader(source.String()), func() bool {
					if armed {
						calls++
						return true
					}
					return false
				})
				if z.Next() != StartTagToken {
					t.Fatal(z.Err())
				}
				// Exercise periodic sampling, not the first-operation check.
				z.guard.stopChecks = 1
				armed = true
				if materialize {
					if token := z.Token(); token.Type != ErrorToken || len(token.Attr) != 0 {
						t.Fatal("cancelled Token returned partial attributes")
					}
				} else {
					for {
						key, val, more := z.TagAttr()
						if !more {
							if key != nil || val != nil {
								t.Fatal("cancelled TagAttr returned data")
							}
							break
						}
					}
				}
				if z.Err() != ErrResourceStopped || calls != 1 {
					t.Fatalf("err=%v calls=%d", z.Err(), calls)
				}
				if !longValue && z.nAttrReturned >= 256 {
					t.Fatalf("processed %d attributes before stopping", z.nAttrReturned)
				}
			})
		}
	}
}
