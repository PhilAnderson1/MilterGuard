package message

import (
	"reflect"
	"testing"
)

func TestHeaderValuesReturnsReadOnlyCopy(t *testing.T) {
	m := New(1000)
	m.AddHeader("Received-SPF", "first")
	m.AddHeader("Received-SPF", "second")

	values := m.HeaderValues("Received-SPF")
	values[0] = "changed"
	if got := m.HeaderValues("received-spf"); !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Fatalf("stored header values changed through returned slice: %q", got)
	}
}
