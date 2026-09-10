package attachment

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func testScanner() *Scanner {
	return New(Options{
		BlockedExtensions: []string{"exe", "bat", "js"}, InspectSignatures: true, InspectArchives: true,
		MaxAttachmentBytes: 1 << 20, MaxArchiveDepth: 2, MaxArchiveFiles: 10, MaxArchiveUncompressedBytes: 2 << 20,
	})
}

func TestDirectAttachmentBlockedByDecodedFilename(t *testing.T) {
	body := []byte("harmless bytes")
	finding, err := testScanner().Scan(
		"application/octet-stream",
		"base64",
		`attachment; filename*=UTF-8''Quarterly%20Report.PDF.EXE`,
		[]byte(base64.StdEncoding.EncodeToString(body)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "Quarterly Report.PDF.EXE" || finding.Detection != "blocked extension .exe" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestSafeAttachmentAllowed(t *testing.T) {
	finding, err := testScanner().Scan("application/pdf", "", `attachment; filename="report.pdf"`, []byte("%PDF-1.7\n"))
	if err != nil || finding != nil {
		t.Fatalf("finding = %#v, error = %v", finding, err)
	}
}

func TestExecutableScriptDetectedDespiteSafeExtension(t *testing.T) {
	finding, err := testScanner().Scan("text/plain", "", `attachment; filename="invoice.txt"`, []byte("#!/usr/bin/env python3\nprint('bad')\n"))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || !strings.Contains(finding.Detection, "python3") {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestWindowsExecutableDetectedByMagicDespiteSafeExtension(t *testing.T) {
	finding, err := testScanner().Scan("application/octet-stream", "", `attachment; filename="invoice.txt"`, []byte("MZnonstandard executable content"))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Detection != "DOS/Windows executable signature" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestPlainMessageBodyIsNotTreatedAsAttachment(t *testing.T) {
	finding, err := testScanner().Scan("", "", "", []byte("#!/bin/sh\necho this is an email body\n"))
	if err != nil || finding != nil {
		t.Fatalf("finding = %#v, error = %v", finding, err)
	}
}

func TestBlockedFilenameDoesNotNeedToBeDecoded(t *testing.T) {
	scanner := testScanner()
	scanner.options.MaxAttachmentBytes = 4
	finding, err := scanner.Scan("application/octet-stream", "base64", `attachment; filename="large.exe"`, []byte(base64.StdEncoding.EncodeToString([]byte("larger than limit"))))
	if err != nil || finding == nil || finding.Detection != "blocked extension .exe" {
		t.Fatalf("finding = %#v, error = %v", finding, err)
	}
}

func TestExecutableSignatureDetectedInSizeLimitedDecode(t *testing.T) {
	scanner := testScanner()
	scanner.options.MaxAttachmentBytes = 16
	payload := append([]byte("MZ"), bytes.Repeat([]byte{0x42}, 100)...)
	finding, err := scanner.Scan("application/octet-stream", "base64", `attachment; filename="invoice.txt"`, []byte(base64.StdEncoding.EncodeToString(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Detection != "DOS/Windows executable signature" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestExecutableSignatureDetectedInTruncatedBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("MZ executable data that continues"))
	encoded = encoded[:len(encoded)-3]
	finding, err := testScanner().Scan("application/octet-stream", "base64", `attachment; filename="invoice.txt"`, []byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Detection != "DOS/Windows executable signature" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestZIPEntryBlockedWithoutExtraction(t *testing.T) {
	archive := makeZIP(t, map[string][]byte{"../../payload.BAT": []byte("echo bad")})
	finding, err := testScanner().Scan("application/zip", "", `attachment; filename="documents.zip"`, archive)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "documents.zip/payload.BAT" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestNestedZIPEntryBlocked(t *testing.T) {
	inner := makeZIP(t, map[string][]byte{"payload.exe": []byte("not actually executable")})
	outer := makeZIP(t, map[string][]byte{"inner.zip": inner})
	finding, err := testScanner().Scan("application/zip", "", `attachment; filename="outer.zip"`, outer)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "outer.zip/inner.zip/payload.exe" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestGzippedTARIsInspected(t *testing.T) {
	var tarData bytes.Buffer
	tarWriter := tar.NewWriter(&tarData)
	payload := []byte("alert('bad')")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "assets/run.js", Mode: 0o600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(tarData.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	finding, err := testScanner().Scan("application/gzip", "", `attachment; filename="bundle.tar.gz"`, compressed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "bundle.tar.gz/bundle.tar/run.js" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestGZIPStoredFilenameIsInspected(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Name = "hidden.exe"
	if _, err := writer.Write([]byte("payload without a signature")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	finding, err := testScanner().Scan("application/gzip", "", `attachment; filename="document.gz"`, compressed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "document.gz/hidden.exe" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestBZIP2ContentIsInspected(t *testing.T) {
	compressed, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWce+TrsAAAJRgAAQaAC+YYgAIAAxTAABCDGpjSCS/XMj11GGMI+LuSKcKEhj3yddgA==")
	if err != nil {
		t.Fatal(err)
	}
	finding, err := testScanner().Scan("application/x-bzip2", "", `attachment; filename="script.txt.bz2"`, compressed)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || !strings.Contains(finding.Detection, "sh") {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestEncryptedZIPIsReported(t *testing.T) {
	archive := makeZIP(t, map[string][]byte{"document.txt": []byte("safe")})
	for offset := 0; offset+10 < len(archive); offset++ {
		switch string(archive[offset : offset+4]) {
		case "PK\x03\x04":
			archive[offset+6] |= 1
		case "PK\x01\x02":
			archive[offset+8] |= 1
		}
	}
	finding, err := testScanner().Scan("application/zip", "", `attachment; filename="encrypted.zip"`, archive)
	var scanErr *ScanError
	if finding != nil || !errors.As(err, &scanErr) || !scanErr.Encrypted {
		t.Fatalf("finding = %#v, error = %#v", finding, err)
	}
}

func TestMultipartScansAllAlternativesAndAttachments(t *testing.T) {
	archive := makeZIP(t, map[string][]byte{"launch.exe": []byte("payload")})
	boundary := "scanner-test-boundary"
	body := fmt.Sprintf("--%s\r\nContent-Type: text/plain\r\n\r\nSafe text\r\n--%s\r\nContent-Type: application/zip; name=files.zip\r\nContent-Disposition: attachment; filename=files.zip\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n--%s--\r\n", boundary, boundary, base64.StdEncoding.EncodeToString(archive), boundary)
	finding, err := testScanner().Scan(`multipart/mixed; boundary="`+boundary+`"`, "", "", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "message/files.zip/launch.exe" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestExecutableSignatureDetectedInTruncatedMultipart(t *testing.T) {
	boundary := "truncated-multipart-boundary"
	encoded := base64.StdEncoding.EncodeToString(append([]byte("MZ"), bytes.Repeat([]byte{0x42}, 100)...))
	body := fmt.Sprintf("--%s\r\nContent-Type: text/plain\r\n\r\ntest\r\n--%s\r\nContent-Type: application/octet-stream; name=invoice.txt\r\nContent-Disposition: attachment; filename=invoice.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n%s", boundary, boundary, encoded[:len(encoded)-3])
	scanner := testScanner()
	scanner.options.MaxAttachmentBytes = 64
	finding, err := scanner.Scan(`multipart/mixed; boundary="`+boundary+`"`, "", "", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "message/invoice.txt" || finding.Detection != "DOS/Windows executable signature" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestExecutableDetectedInsideTruncatedAttachedEmail(t *testing.T) {
	innerBoundary := "inner-email-boundary"
	encoded := base64.StdEncoding.EncodeToString(append([]byte("MZ"), bytes.Repeat([]byte{0x42}, 100)...))
	attachedEmail := fmt.Sprintf("From: sender@example.net\r\nTo: recipient@example.net\r\nContent-Type: multipart/mixed; boundary=%s\r\n\r\n--%s\r\nContent-Type: text/plain\r\n\r\ntest\r\n--%s\r\nContent-Type: application/octet-stream; name=p2s.txt\r\nContent-Disposition: attachment; filename=p2s.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n%s", innerBoundary, innerBoundary, innerBoundary, encoded[:len(encoded)-3])
	outerBoundary := "outer-email-boundary"
	body := fmt.Sprintf("--%s\r\nContent-Type: text/plain\r\n\r\nForwarded message\r\n--%s\r\nContent-Type: message/rfc822; name=test.eml\r\nContent-Disposition: attachment; filename=test.eml\r\n\r\n%s", outerBoundary, outerBoundary, attachedEmail)
	finding, err := testScanner().Scan(`multipart/mixed; boundary="`+outerBoundary+`"`, "", "", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "message/test.eml/p2s.txt" || finding.Detection != "DOS/Windows executable signature" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestExecutableDetectedInsideTruncatedZIPAndMIME(t *testing.T) {
	payload := make([]byte, 256<<10)
	payload[0], payload[1] = 'M', 'Z'
	seed := uint32(1)
	for index := 2; index < len(payload); index++ {
		seed = seed*1664525 + 1013904223
		payload[index] = byte(seed >> 24)
	}
	archive := makeZIP(t, map[string][]byte{"p2s.txt": payload})
	encoded := base64.StdEncoding.EncodeToString(archive)
	encoded = encoded[:len(encoded)/2]
	boundary := "truncated-zip-mime-boundary"
	body := fmt.Sprintf("--%s\r\nContent-Type: text/plain\r\n\r\ntest\r\n--%s\r\nContent-Type: application/zip; name=p2s.zip\r\nContent-Disposition: attachment; filename=p2s.zip\r\nContent-Transfer-Encoding: base64\r\n\r\n%s", boundary, boundary, encoded)
	finding, err := testScanner().Scan(`multipart/mixed; boundary="`+boundary+`"`, "", "", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "message/p2s.zip/p2s.txt" || finding.Detection != "DOS/Windows executable signature" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestArchiveLimitsAreEnforced(t *testing.T) {
	scanner := testScanner()
	scanner.options.MaxArchiveFiles = 1
	archive := makeZIP(t, map[string][]byte{"one.txt": []byte("one"), "two.txt": []byte("two")})
	finding, err := scanner.Scan("application/zip", "", `attachment; filename="many.zip"`, archive)
	if finding != nil || err == nil || !strings.Contains(err.Error(), "file-count limit") {
		t.Fatalf("finding = %#v, error = %v", finding, err)
	}
}

func TestPartialZIPUnderstatedSizesCannotBypassActualByteBudget(t *testing.T) {
	scanner := testScanner()
	scanner.options.MaxAttachmentBytes = 1024
	scanner.options.MaxArchiveUncompressedBytes = 20
	archive := append(partialZIPEntry(t, "one.txt", bytes.Repeat([]byte("a"), 16), 1),
		partialZIPEntry(t, "two.txt", bytes.Repeat([]byte("b"), 16), 1)...)

	finding, err := scanner.Scan("application/zip", "", `attachment; filename="partial.zip"`, archive)
	if finding != nil || err == nil || !strings.Contains(err.Error(), "archive uncompressed-size limit exceeded") {
		t.Fatalf("finding = %#v, error = %v", finding, err)
	}
}

func TestDeclaredArchiveLimitRejectedBeforeReading(t *testing.T) {
	scanner := testScanner()
	state := &scanState{archiveBytes: scanner.options.MaxArchiveUncompressedBytes - 1}
	if err := scanner.beginArchiveFile(2, state); err == nil || !strings.Contains(err.Error(), "archive uncompressed-size limit exceeded") {
		t.Fatalf("error = %v", err)
	}
	if state.archiveFiles != 0 || state.archiveBytes != scanner.options.MaxArchiveUncompressedBytes-1 {
		t.Fatalf("state changed after rejected declaration: %#v", state)
	}
}

func TestInvalidArchiveReportedAsUnscannable(t *testing.T) {
	finding, err := testScanner().Scan("application/zip", "", `attachment; filename="broken.zip"`, []byte("not a zip"))
	if finding != nil || err == nil || !strings.Contains(err.Error(), "invalid ZIP") {
		t.Fatalf("finding = %#v, error = %v", finding, err)
	}
}

func makeZIP(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for name, data := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func partialZIPEntry(t *testing.T, name string, content []byte, declaredSize uint32) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 30)
	binary.LittleEndian.PutUint32(header[0:4], 0x04034b50)
	binary.LittleEndian.PutUint16(header[4:6], 20)
	binary.LittleEndian.PutUint16(header[8:10], zip.Deflate)
	binary.LittleEndian.PutUint32(header[18:22], uint32(compressed.Len()))
	binary.LittleEndian.PutUint32(header[22:26], declaredSize)
	binary.LittleEndian.PutUint16(header[26:28], uint16(len(name)))
	entry := append(header, name...)
	return append(entry, compressed.Bytes()...)
}
