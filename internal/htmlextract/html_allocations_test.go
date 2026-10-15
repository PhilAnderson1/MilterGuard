package htmlextract

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

func formattingExpansionPrefix() string {
	prefix := "<p>"
	for _, name := range []string{"b", "big", "code", "em", "font", "i", "s", "small", "strike", "strong", "tt", "u"} {
		prefix += strings.Repeat("<"+name+">", 3)
	}
	return prefix
}

func TestAllocationPreflightRejectsExpansionBeforeTreeConstruction(t *testing.T) {
	var attributes strings.Builder
	for i := range 100 {
		fmt.Fprintf(&attributes, " a%d=x", i)
	}
	for _, c := range []struct{ name, source string }{
		{"implied table wrappers", strings.Repeat(`<table><td></table>`, 33330)},
		{"formatting reconstruction", formattingExpansionPrefix() + `seed</p>` + strings.Repeat(`<p>x</p>`, 3000)},
		{"copied formatting attributes", `<p><b` + attributes.String() + `>seed</p>` + strings.Repeat(`<p>x</p>`, 600)},
		{"ignored close inside object scope", `<div><object>` + formattingExpansionPrefix() + `seed</div>` + strings.Repeat(`<p>x</p>`, 3000)},
		{"MathML formatting integration", `<math><mtext>` + formattingExpansionPrefix() + `seed</p>` + strings.Repeat(`<p>x</p>`, 3000)},
	} {
		t.Run(c.name, func(t *testing.T) {
			document, err := (processor{Limits: DefaultLimits()}).parseDocument([]byte(c.source))
			if err == nil || !strings.Contains(err.Error(), "projected tree allocations") {
				t.Fatalf("expected allocation preflight rejection, got %v", err)
			}
			if document.root != nil {
				t.Fatal("allocating parser ran before the expansion was rejected")
			}
		})
	}
}

func TestAllocationPreflightKeepsOrdinaryFormattingAndCellScopes(t *testing.T) {
	for _, c := range []struct{ name, source string }{
		{"balanced formatting", strings.Repeat(`<p><b>bold</b></p>`, 10000)},
		{"attributed formatting around paragraphs", strings.Repeat(`<b class="bold"><p>x</p></b>`, 1000)},
		{"Noahs Ark identical entries", strings.Repeat(`<p><b>x`, 3000)},
		{"cell-local unclosed fonts", `<table><tr>` + strings.Repeat(`<td><font color="red">x</td>`, 1000) + `</tr></table>`},
		{"optional cell ends", `<table><tr>` + strings.Repeat(`<td><font color="red">x`, 1000) + `</table>`},
		{"links separated by cell markers", strings.Repeat(`<a href="#outer"><table><tr><td><a href="#inner">x</a></td></tr></table></a>`, 1000)},
		{"unmatched closes before empty cell scopes", `</span><table><tr>` + strings.Repeat(`<td>x</td>`, 1000) + `</tr></table>`},
		{"SVG links are not HTML formatting", `<svg>` + strings.Repeat(`<a href="#"><text>x</text></a>`, 1000) + `</svg>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Analyze([]byte(c.source), DefaultLimits()); err != nil {
				t.Fatalf("ordinary bounded input rejected: %v", err)
			}
		})
	}
}

func TestAllocationProjectionAgainstTreeBuilder(t *testing.T) {
	// Malformed combinations exercise adoption, ignored closes, markers,
	// foreign integration, and table insertion modes against the actual parser.
	random := rand.New(rand.NewSource(39))
	prefixes := []string{"", `<p><b><i><em>seed</p>`, `<div><object><p><b><i>`, `<table><tr><td><b>`, `<math><mtext><a>`}
	tokens := []string{"x", " ", `<p>`, `</p>`, `<div>`, `</div>`, `<b>`, `</b>`, `<i class="x">`, `</i>`, `<a>`, `</a>`, `<table>`, `</table>`, `<tr>`, `</tr>`, `<td>`, `</td>`, `<object>`, `</object>`, `<template>`, `</template>`, `<svg>`, `</svg>`, `<mtext>`, `<span>`, `</span>`, `</br>`, `<select>`, `</select>`, `<option>`, `<button>`, `</button>`, `<form>`, `</form>`, `<caption>`, `</caption>`, `<math>`, `</math>`, `<foreignObject>`, `</foreignObject>`, `<li>`, `</li>`, `<h1>`, `</h1>`, `<nobr>`, `</nobr>`, `<font>`, `<font color="red" size="2">`, `</font>`, `<marquee>`, `</marquee>`, `<applet>`, `</applet>`}
	limits := DefaultLimits()
	limits.Nodes = 1000
	limits.Attributes = 1000
	limits.Depth = 64
	for range 50000 {
		var source strings.Builder
		source.WriteString(prefixes[random.Intn(len(prefixes))])
		for range 40 {
			source.WriteString(tokens[random.Intn(len(tokens))])
		}
		input := source.String()
		usage, err := measurePreflight([]byte(input), limits)
		if err != nil {
			continue
		}
		root, err := html.ParseWithOptions(strings.NewReader(input), html.ParseOptionEnableScripting(false))
		if err != nil {
			t.Fatalf("admitted parser error %v: %s", err, input)
		}
		nodes, attributes := 0, 0
		stack := []*html.Node{root}
		for len(stack) > 0 {
			node := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			nodes++
			attributes += len(node.Attr)
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				stack = append(stack, child)
			}
		}
		if nodes > usage.projectedNodes+4 || attributes > usage.projectedAttributes {
			t.Fatalf("allocation projection too small: nodes=%d attributes=%d preflight=%+v input=%s", nodes, attributes, usage, input)
		}
	}
}

func TestAllocationPreflightChecksCancellationDuringAttributes(t *testing.T) {
	var source strings.Builder
	source.WriteString(`<b`)
	for i := range 1000 {
		fmt.Fprintf(&source, ` x%d="value"`, i)
	}
	source.WriteByte('>')
	usage, err := measurePreflightWithStop([]byte(source.String()), DefaultLimits(), func() bool { return true })
	if !IsStopped(err) || usage.attributes != 0 {
		t.Fatalf("attribute scan ignored cancellation: usage=%+v error=%v", usage, err)
	}
}
