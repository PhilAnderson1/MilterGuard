//go:build ignore

// Usage: go run reassemble.go CAPTURE.json OUTPUT.eml
// Reassembles the conventional Postfix Milter message representation. Postfix
// removes one separator space after the colon, so it is added back here.
package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

type event struct {
	Command string `json:"command"`
	Name    string `json:"name,omitempty"`
	Value   string `json:"value,omitempty"`
	Hex     string `json:"hex"`
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: reassemble CAPTURE.json OUTPUT.eml")
	}
	b, err := os.ReadFile(os.Args[1])
	check(err)
	var events []event
	check(json.Unmarshal(b, &events))
	var output []byte
	for _, event := range events {
		switch event.Command {
		case "header":
			output = append(output, event.Name...)
			output = append(output, ':', ' ')
			output = append(output, strings.ReplaceAll(event.Value, "\n", "\r\n")...)
			output = append(output, '\r', '\n')
		case "eoh":
			output = append(output, '\r', '\n')
		case "body":
			body, err := hex.DecodeString(event.Hex)
			check(err)
			output = append(output, body...)
		}
	}
	check(os.WriteFile(os.Args[2], output, 0600))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
