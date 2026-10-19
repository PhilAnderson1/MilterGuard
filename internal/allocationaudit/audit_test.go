package allocationaudit

import (
	"encoding/json"
	"os"
	"testing"
)

func TestReviewedAllocationEffects(t *testing.T) {
	root := "../.."
	actual, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/approved-effects.json")
	if err != nil {
		t.Fatal(err)
	}
	var approved map[string]string
	if err = json.Unmarshal(data, &approved); err != nil {
		t.Fatal(err)
	}
	for id, hash := range actual {
		if approved[id] != hash {
			t.Errorf("allocation effects need review: %s (see internal/allocationaudit/README.md)", id)
		}
	}
	for id := range approved {
		if _, ok := actual[id]; !ok {
			t.Errorf("retired allocation owner needs ledger update: %s", id)
		}
	}
}
