// exactdkim-prototype captures the bytes Postfix sends through the Milter
// protocol. It is deliberately separate from the production MilterGuard
// module: its only purpose is deciding the exact-DKIM feasibility gate.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const (
	optneg   = byte('O')
	header   = byte('L')
	body     = byte('B')
	eoh      = byte('N')
	eom      = byte('E')
	abort    = byte('A')
	quit     = byte('Q')
	quitConn = byte('K')
	cont     = byte('c')
	accept   = byte('a')
)

type event struct {
	Command string `json:"command"`
	Name    string `json:"name,omitempty"`
	Value   string `json:"value,omitempty"`
	Hex     string `json:"hex"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18895", "Milter TCP listen address")
	output := flag.String("output", "capture.json", "capture output file")
	flag.Parse()
	ln, err := net.Listen("tcp", *listen)
	check(err)
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "listening on %s\n", ln.Addr())
	c, err := ln.Accept()
	check(err)
	defer c.Close()
	var events []event
	r := bufio.NewReader(c)
	for {
		payload, err := readFrame(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			check(err)
		}
		cmd := payload[0]
		ev := event{Command: commandName(cmd), Hex: hex.EncodeToString(payload[1:])}
		if cmd == header {
			parts := bytes.Split(payload[1:], []byte{0})
			if len(parts) == 3 && len(parts[2]) == 0 {
				ev.Name, ev.Value = string(parts[0]), string(parts[1])
			}
		}
		events = append(events, ev)
		switch cmd {
		case optneg:
			if len(payload) != 13 {
				check(fmt.Errorf("option frame has %d bytes", len(payload)))
			}
			response := append([]byte(nil), payload...)
			binary.BigEndian.PutUint32(response[5:9], 0)
			binary.BigEndian.PutUint32(response[9:13], 0)
			check(writeFrame(c, response))
		case eom:
			check(writeFrame(c, []byte{accept}))
			check(writeJSON(*output, events))
			return
		case abort:
			events = nil
		case quit, quitConn:
			check(writeJSON(*output, events))
			return
		default:
			check(writeFrame(c, []byte{cont}))
		}
	}
	check(writeJSON(*output, events))
}

func readFrame(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("invalid frame length %d", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeFrame(w io.Writer, payload []byte) error {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(payload)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func writeJSON(path string, events []event) error {
	b, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

func commandName(c byte) string {
	names := map[byte]string{'A': "abort", 'B': "body", 'C': "connect", 'D': "macro", 'E': "eom", 'H': "helo", 'K': "quit-connection", 'L': "header", 'M': "mail", 'N': "eoh", 'O': "option", 'Q': "quit", 'R': "recipient", 'T': "data", 'U': "unknown"}
	if name := names[c]; name != "" {
		return name
	}
	return fmt.Sprintf("0x%02x", c)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, strings.TrimSpace(err.Error()))
		os.Exit(1)
	}
}
