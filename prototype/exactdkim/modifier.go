//go:build ignore

// Usage: go run modifier.go
// A deliberately tiny earlier Milter that adds an unsigned header at EOM.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	commandOption = byte('O')
	commandEOM    = byte('E')
	commandQuit   = byte('Q')
	commandQuitNC = byte('K')
	responseCont  = byte('c')
	responseAdd   = byte('h')
	responseChg   = byte('m')
	responseOK    = byte('a')
	actionAdd     = uint32(1)
	actionChange  = uint32(0x10)
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:18894")
	check(err)
	defer ln.Close()
	fmt.Println("earlier modifier listening on 127.0.0.1:18894")
	for {
		c, err := ln.Accept()
		check(err)
		done, err := handle(c)
		_ = c.Close()
		check(err)
		if done {
			return
		}
	}
}

func handle(c net.Conn) (bool, error) {
	r := bufio.NewReader(c)
	for {
		frame, err := readFrame(r)
		if err != nil {
			if err == io.EOF {
				return false, nil
			}
			return false, err
		}
		switch frame[0] {
		case commandOption:
			response := append([]byte(nil), frame...)
			offered := binary.BigEndian.Uint32(frame[5:9])
			binary.BigEndian.PutUint32(response[5:9], offered&(actionAdd|actionChange))
			binary.BigEndian.PutUint32(response[9:13], 0)
			if err := writeFrame(c, response); err != nil {
				return false, err
			}
		case commandEOM:
			change := []byte{responseChg, 0, 0, 0, 1}
			change = append(change, []byte("Subject\x00changed by earlier Milter\x00")...)
			if err := writeFrame(c, change); err != nil {
				return false, err
			}
			if err := writeFrame(c, append([]byte{responseAdd}, []byte("X-Earlier-Milter\x00added before verifier\x00")...)); err != nil {
				return false, err
			}
			if err := writeFrame(c, []byte{responseOK}); err != nil {
				return false, err
			}
			return true, nil
		case commandQuit, commandQuitNC:
			return false, nil
		default:
			if err := writeFrame(c, []byte{responseCont}); err != nil {
				return false, err
			}
		}
	}
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

func check(err error) {
	if err != nil {
		panic(err)
	}
}
