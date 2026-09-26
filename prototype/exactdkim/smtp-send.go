//go:build ignore

// Usage: go run smtp-send.go ADDRESS MESSAGE.eml
// Sends the file as SMTP DATA without canonicalising its line endings.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: smtp-send ADDRESS MESSAGE.eml")
	}
	message, err := os.ReadFile(os.Args[2])
	check(err)
	if bytes.Contains(message, []byte("\r\n")) {
		withoutCRLF := bytes.ReplaceAll(message, []byte("\r\n"), nil)
		if bytes.ContainsAny(withoutCRLF, "\r\n") {
			panic("fixture has mixed or bare line endings")
		}
	} else {
		message = bytes.ReplaceAll(message, []byte{'\n'}, []byte("\r\n"))
	}
	c, err := net.Dial("tcp", os.Args[1])
	check(err)
	defer c.Close()
	r := bufio.NewReader(c)
	readReply(r, '2')
	command(c, r, "EHLO sender.example.test\r\n", '2')
	command(c, r, "MAIL FROM:<alice@example.test>\r\n", '2')
	command(c, r, "RCPT TO:<bob@example.test>\r\n", '2')
	command(c, r, "DATA\r\n", '3')
	if len(message) > 0 && message[0] == '.' {
		_, _ = c.Write([]byte{'.'})
	}
	message = bytes.ReplaceAll(message, []byte("\r\n."), []byte("\r\n.."))
	_, _ = c.Write(message)
	if !bytes.HasSuffix(message, []byte("\r\n")) {
		_, _ = c.Write([]byte("\r\n"))
	}
	_, _ = c.Write([]byte(".\r\n"))
	readReply(r, '2')
	command(c, r, "QUIT\r\n", '2')
}

func command(c net.Conn, r *bufio.Reader, s string, want byte) {
	_, err := c.Write([]byte(s))
	check(err)
	readReply(r, want)
}

func readReply(r *bufio.Reader, want byte) {
	for {
		line, err := r.ReadString('\n')
		check(err)
		fmt.Print(line)
		if len(line) < 4 || line[0] != want {
			panic("unexpected SMTP reply: " + strings.TrimSpace(line))
		}
		if line[3] == ' ' {
			return
		}
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
