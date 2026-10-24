package message

import "testing"

func TestSelectProcessedBodyBoundaries(t *testing.T) {
	const truncatedMarker = "\n[processed email body truncated; the remainder was omitted]"
	const incompleteMarker = "\n[Content extraction incomplete; some content may be missing]"
	for _, test := range []struct {
		name      string
		content   extractedContent
		limit     int
		want      string
		truncated bool
		stripped  bool
	}{
		{name: "empty", limit: 0},
		{name: "zero limit", content: extractedContent{Text: "é"}, limit: 0, truncated: true},
		{name: "negative limit", content: extractedContent{Text: "é"}, limit: -1, truncated: true},
		{name: "Unicode exact fit", content: extractedContent{Text: "aé😀"}, limit: 3, want: "aé😀"},
		{name: "Unicode truncation", content: extractedContent{Text: "aé😀z"}, limit: 3, want: "aé😀" + truncatedMarker, truncated: true},
		{name: "keep fitting concealed body", content: extractedContent{Text: "aé😀", HasConcealedContent: true, StrippedText: "x"}, limit: 3, want: "aé😀"},
		{name: "stripped exact fit", content: extractedContent{Text: "hidden aé😀", HasConcealedContent: true, StrippedText: "aé😀"}, limit: 3, want: "aé😀", stripped: true},
		{name: "stripped still overlong", content: extractedContent{Text: "hidden aé😀z", HasConcealedContent: true, StrippedText: "aé😀z"}, limit: 3, want: "aé😀" + truncatedMarker, truncated: true, stripped: true},
		{name: "stripped empty", content: extractedContent{Text: "hidden", HasConcealedContent: true}, limit: 3, stripped: true},
		{name: "incomplete after truncation", content: extractedContent{Text: "aé😀z", ExtractionIncomplete: true}, limit: 3, want: "aé😀" + truncatedMarker + incompleteMarker, truncated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, truncated, stripped := selectProcessedBody(test.content, test.limit)
			if body != test.want || truncated != test.truncated || stripped != test.stripped {
				t.Fatalf("got (%q, %t, %t), want (%q, %t, %t)", body, truncated, stripped, test.want, test.truncated, test.stripped)
			}
		})
	}
}
