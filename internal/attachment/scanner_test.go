package attachment

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func testScanner() *Scanner {
	return New(Options{
		BlockedExtensions: []string{"exe", "bat", "js"}, InspectSignatures: true, InspectArchives: true,
		MaxAttachmentBytes: 1 << 20, MaxArchiveDepth: 2, MaxArchiveFiles: 10, MaxArchiveUncompressedBytes: 2 << 20,
	})
}

func TestScanContextStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	finding, err := testScanner().ScanContext(ctx,
		"application/octet-stream", "", `attachment; filename="document.txt"`, []byte("content"))
	if finding != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scan = finding %#v, error %v", finding, err)
	}
}

type cancelAfterRead struct {
	reader io.Reader
	cancel context.CancelFunc
}

func (reader *cancelAfterRead) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.cancel()
	return count, err
}

func TestArchiveReadStopsAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	state := &scanState{ctx: ctx}
	scanner := testScanner()
	_, err := scanner.readArchiveEntry(&cancelAfterRead{
		reader: bytes.NewReader(bytes.Repeat([]byte("x"), 1024)), cancel: cancel,
	}, state)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("archive cancellation error = %v, want context.Canceled", err)
	}
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

func TestNTFSStreamSuffixDoesNotHideBlockedExtension(t *testing.T) {
	for _, filename := range []string{"invoice.exe::$DATA", "script.bat:stream"} {
		t.Run(filename, func(t *testing.T) {
			finding, err := testScanner().Scan(
				"application/octet-stream", "", `attachment; filename="`+filename+`"`, []byte("harmless bytes"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if finding == nil || !strings.Contains(finding.Detection, "blocked extension") {
				t.Fatalf("finding = %#v", finding)
			}
		})
	}
}

func TestNTFSStreamSuffixInsideArchiveDoesNotHideBlockedExtension(t *testing.T) {
	archive := makeZIP(t, map[string][]byte{"script.bat:stream": []byte("harmless bytes")})
	finding, err := testScanner().Scan("application/zip", "", `attachment; filename="files.zip"`, archive)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Detection != "blocked extension .bat" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestUnicodeIgnorablesAndCompatibilityCharactersDoNotHideBlockedExtension(t *testing.T) {
	for _, filename := range []string{
		"invoice.js\u200d",
		"invoice.\u202ejs",
		"invoice.js\ufe0f",
		"invoice.j\u034fs",
		"invoice.ｊｓ",
	} {
		t.Run(filename, func(t *testing.T) {
			finding, err := testScanner().Scan(
				"application/octet-stream", "", `attachment; filename="`+filename+`"`, []byte("harmless bytes"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if finding == nil || finding.Detection != "blocked extension .js" {
				t.Fatalf("finding = %#v", finding)
			}
		})
	}
}

func TestUnicodeIgnorableInsideArchiveDoesNotHideBlockedExtension(t *testing.T) {
	archive := makeZIP(t, map[string][]byte{"invoice.js\u200d": []byte("harmless bytes")})
	finding, err := testScanner().Scan("application/zip", "", `attachment; filename="files.zip"`, archive)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "files.zip/invoice.js" || finding.Detection != "blocked extension .js" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestCleanNameRetainsOrdinaryInternationalCharacters(t *testing.T) {
	if got, want := cleanName("ご案内.pdf"), "ご案内.pdf"; got != want {
		t.Fatalf("cleanName() = %q, want %q", got, want)
	}
}

func TestCleanNamePreservesOrdinaryColonFilename(t *testing.T) {
	if got, want := cleanName("report:final.pdf"), "report:final.pdf"; got != want {
		t.Fatalf("cleanName() = %q, want %q", got, want)
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

func TestUnpaddedSafeBase64IsReportedAsIncompleteInspection(t *testing.T) {
	encoded := strings.TrimRight(base64.StdEncoding.EncodeToString([]byte("safe")), "=")
	finding, err := testScanner().Scan("application/octet-stream", "base64", `attachment; filename="invoice.txt"`, []byte(encoded))
	var scanErr *ScanError
	if finding != nil || !errors.As(err, &scanErr) {
		t.Fatalf("finding = %#v, error = %#v; want an incomplete-inspection error", finding, err)
	}
	if scanErr.Path != "invoice.txt" {
		t.Fatalf("error path = %q, want invoice.txt", scanErr.Path)
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

func TestMultipartFindingTakesPrecedenceOverEarlierPartError(t *testing.T) {
	boundary := "malformed-part-before-executable"
	body := fmt.Sprintf("--%s\r\nContent-Type: text/plain; charset=\"\r\n\r\nbroken\r\n--%s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=payload.exe\r\n\r\npayload\r\n--%s--\r\n", boundary, boundary, boundary)
	finding, err := testScanner().Scan(`multipart/mixed; boundary="`+boundary+`"`, "", "", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "message/payload.exe" || finding.Detection != "blocked extension .exe" {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestMultipartReturnsEarlierPartErrorAfterScanningRemainingParts(t *testing.T) {
	boundary := "malformed-part-before-safe-part"
	body := fmt.Sprintf("--%s\r\nContent-Type: text/plain; charset=\"\r\n\r\nbroken\r\n--%s\r\nContent-Type: text/plain\r\n\r\nsafe\r\n--%s--\r\n", boundary, boundary, boundary)
	finding, err := testScanner().Scan(`multipart/mixed; boundary="`+boundary+`"`, "", "", []byte(body))
	if finding != nil || err == nil || !strings.Contains(err.Error(), "invalid Content-Type") {
		t.Fatalf("finding = %#v, error = %v", finding, err)
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

func TestMultipartDigestScansImplicitAttachedMessage(t *testing.T) {
	attachedEmail := "From: sender@example.net\r\n" +
		"Content-Type: application/octet-stream; name=invoice.exe\r\n" +
		"Content-Disposition: attachment; filename=invoice.exe\r\n\r\n" +
		"executable content"
	body := "--digest\r\n\r\n" + attachedEmail + "\r\n--digest--\r\n"
	finding, err := testScanner().Scan(`multipart/digest; boundary="digest"`, "", "", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "invoice.exe" || finding.Detection != "blocked extension .exe" {
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

func TestMIMEDepthLimitUsesOneConsistentBoundary(t *testing.T) {
	scanner := testScanner()
	finding, err := scanner.scanMIME("text/plain", "", "", []byte("safe"), "message", maxMIMEDepth-1, &scanState{})
	if finding != nil || err != nil {
		t.Fatalf("last permitted MIME depth: finding = %#v, error = %v", finding, err)
	}
	finding, err = scanner.scanMIME("text/plain", "", "", []byte("safe"), "message", maxMIMEDepth, &scanState{})
	if finding != nil || err == nil || !strings.Contains(err.Error(), "MIME nesting limit") {
		t.Fatalf("excessive MIME depth: finding = %#v, error = %v", finding, err)
	}
}

func TestArchiveLimitProbeToleratesZeroLengthRead(t *testing.T) {
	scanner := testScanner()
	scanner.options.MaxAttachmentBytes = 4
	reader := &zeroBeforeExtraReader{content: []byte("12345")}
	data, err := scanner.readArchiveEntry(reader, &scanState{})
	if string(data) != "1234" || err == nil || !strings.Contains(err.Error(), "entry size limit") {
		t.Fatalf("data = %q, error = %v", data, err)
	}
}

func TestTARChecksExecutableSignatureInPartialEntry(t *testing.T) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "invoice.txt", Mode: 0o600, Size: 10}); err != nil {
		t.Fatal(err)
	}
	archive.WriteString("MZ")

	finding, err := testScanner().scanTAR("files.tar", bytes.NewReader(archive.Bytes()), 1, &scanState{})
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.Path != "files.tar/invoice.txt" || finding.Detection != "DOS/Windows executable signature" {
		t.Fatalf("finding = %#v", finding)
	}
}

type zeroBeforeExtraReader struct {
	content     []byte
	offset      int
	returnedNil bool
}

func (r *zeroBeforeExtraReader) Read(p []byte) (int, error) {
	if r.offset == 4 && !r.returnedNil {
		r.returnedNil = true
		return 0, nil
	}
	if r.offset >= len(r.content) {
		return 0, io.EOF
	}
	n := copy(p, r.content[r.offset:])
	r.offset += n
	return n, nil
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
