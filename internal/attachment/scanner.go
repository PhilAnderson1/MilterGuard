package attachment

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxMIMEDepth = 16

type Options struct {
	BlockedExtensions           []string
	InspectSignatures           bool
	InspectArchives             bool
	MaxAttachmentBytes          int64
	MaxArchiveDepth             int
	MaxArchiveFiles             int
	MaxArchiveUncompressedBytes int64
}

type Finding struct {
	Path      string
	Detection string
}

type ScanError struct {
	Path      string
	Encrypted bool
	Err       error
}

func (e *ScanError) Error() string {
	if e.Path == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

func (e *ScanError) Unwrap() error { return e.Err }

type Scanner struct {
	options Options
	blocked map[string]struct{}
}

type scanState struct {
	archiveFiles int
	archiveBytes int64
}

func New(options Options) *Scanner {
	blocked := make(map[string]struct{}, len(options.BlockedExtensions))
	for _, extension := range options.BlockedExtensions {
		extension = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(extension)), ".")
		if extension != "" {
			blocked[extension] = struct{}{}
		}
	}
	return &Scanner{options: options, blocked: blocked}
}

func (s *Scanner) Scan(contentType, transferEncoding, contentDisposition string, body []byte) (*Finding, error) {
	return s.scanMIME(contentType, transferEncoding, contentDisposition, body, "message", 0, &scanState{})
}

func (s *Scanner) scanMIME(contentType, transferEncoding, contentDisposition string, data []byte, location string, mimeDepth int, state *scanState) (*Finding, error) {
	if mimeDepth > maxMIMEDepth {
		return nil, &ScanError{Path: location, Err: errors.New("MIME nesting limit exceeded")}
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if strings.TrimSpace(contentType) == "" {
		mediaType = "text/plain"
		params = nil
	} else if err != nil {
		return nil, &ScanError{Path: location, Err: fmt.Errorf("invalid Content-Type: %w", err)}
	} else if mediaType == "" {
		return nil, &ScanError{Path: location, Err: errors.New("empty Content-Type")}
	}
	mediaType = strings.ToLower(mediaType)
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return nil, &ScanError{Path: location, Err: errors.New("multipart content has no boundary")}
		}
		reader := multipart.NewReader(bytes.NewReader(data), boundary)
		for index := 1; ; index++ {
			part, partErr := reader.NextPart()
			if partErr == io.EOF {
				return nil, nil
			}
			if partErr != nil {
				return nil, &ScanError{Path: location, Err: fmt.Errorf("cannot read MIME part: %w", partErr)}
			}
			// The complete message has already been bounded by milter.max_message_size.
			// Keep encoded multipart data intact here so base64 overhead does not count
			// against the decoded attachment limit.
			partData, readErr := io.ReadAll(part)
			partLocation := fmt.Sprintf("%s/part-%d", location, index)
			if filename := attachmentFilename(part.Header.Get("Content-Disposition"), part.Header.Get("Content-Type")); filename != "" {
				partLocation = joinLocation(location, filename)
			}
			finding, scanErr := s.scanMIME(part.Header.Get("Content-Type"), part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Disposition"), partData, partLocation, mimeDepth+1, state)
			if finding != nil || scanErr != nil {
				return finding, scanErr
			}
			if readErr != nil {
				return nil, &ScanError{Path: partLocation, Err: readErr}
			}
		}
	}

	filename := attachmentFilename(contentDisposition, contentType)
	if filename != "" {
		location = replaceLocationBase(location, filename)
		if extension := s.blockedExtension(filename); extension != "" {
			return &Finding{Path: cleanLocation(location), Detection: "blocked extension ." + extension}, nil
		}
	}
	decoded, err := decodeTransfer(transferEncoding, data, s.options.MaxAttachmentBytes)
	if err != nil {
		if s.options.InspectSignatures {
			if signature := executableSignature(decoded); signature != "" {
				return &Finding{Path: cleanLocation(location), Detection: signature}, nil
			}
		}
		if mediaType == "message/rfc822" || strings.HasSuffix(strings.ToLower(filename), ".eml") {
			if finding, nestedErr := s.scanRFC822(decoded, location, mimeDepth, state); finding != nil || nestedErr != nil {
				return finding, nestedErr
			}
		}
		if s.options.InspectArchives && archiveFormat(filename, mediaType, decoded) != "" {
			if finding, _ := s.scanFile(location, filename, mediaType, decoded, 0, state); finding != nil {
				return finding, nil
			}
		}
		return nil, &ScanError{Path: location, Err: err}
	}
	if filename == "" && (mediaType == "text/plain" || mediaType == "text/html") {
		return nil, nil
	}
	if mediaType == "message/rfc822" || strings.HasSuffix(strings.ToLower(filename), ".eml") {
		return s.scanRFC822(decoded, location, mimeDepth, state)
	}
	return s.scanFile(location, filename, mediaType, decoded, 0, state)
}

func (s *Scanner) scanRFC822(data []byte, location string, mimeDepth int, state *scanState) (*Finding, error) {
	if mimeDepth >= maxMIMEDepth {
		return nil, &ScanError{Path: location, Err: errors.New("attached-message nesting limit exceeded")}
	}
	attached, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, &ScanError{Path: location, Err: fmt.Errorf("invalid attached email: %w", err)}
	}
	body, err := io.ReadAll(attached.Body)
	if err != nil {
		return nil, &ScanError{Path: location, Err: fmt.Errorf("cannot read attached email: %w", err)}
	}
	return s.scanMIME(
		attached.Header.Get("Content-Type"),
		attached.Header.Get("Content-Transfer-Encoding"),
		attached.Header.Get("Content-Disposition"),
		body,
		location,
		mimeDepth+1,
		state,
	)
}

func (s *Scanner) scanFile(location, filename, mediaType string, data []byte, archiveDepth int, state *scanState) (*Finding, error) {
	if extension := s.blockedExtension(filename); extension != "" {
		return &Finding{Path: cleanLocation(location), Detection: "blocked extension ." + extension}, nil
	}
	if s.options.InspectSignatures {
		if signature := executableSignature(data); signature != "" {
			return &Finding{Path: cleanLocation(location), Detection: signature}, nil
		}
	}
	if !s.options.InspectArchives {
		return nil, nil
	}
	format := archiveFormat(filename, mediaType, data)
	if format == "" {
		return nil, nil
	}
	if archiveDepth >= s.options.MaxArchiveDepth {
		return nil, &ScanError{Path: cleanLocation(location), Err: errors.New("archive nesting limit exceeded")}
	}
	switch format {
	case "zip":
		return s.scanZIP(location, data, archiveDepth+1, state)
	case "tar":
		return s.scanTAR(location, bytes.NewReader(data), archiveDepth+1, state)
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, &ScanError{Path: cleanLocation(location), Err: fmt.Errorf("invalid gzip archive: %w", err)}
		}
		storedName := strings.TrimSpace(reader.Name)
		if err := s.beginArchiveFile(0, state); err != nil {
			_ = reader.Close()
			return nil, &ScanError{Path: cleanLocation(location), Err: err}
		}
		decompressed, err := s.readArchiveEntry(reader, state)
		_ = reader.Close()
		if err != nil {
			return nil, &ScanError{Path: cleanLocation(location), Err: err}
		}
		innerName := ""
		if storedName != "" {
			innerName = cleanName(storedName)
		} else {
			innerName = stripCompressionExtension(filename, ".gz", ".gzip")
		}
		return s.scanFile(joinLocation(location, innerName), innerName, "application/octet-stream", decompressed, archiveDepth+1, state)
	case "bzip2":
		if err := s.beginArchiveFile(0, state); err != nil {
			return nil, &ScanError{Path: cleanLocation(location), Err: err}
		}
		decompressed, err := s.readArchiveEntry(bzip2.NewReader(bytes.NewReader(data)), state)
		if err != nil {
			return nil, &ScanError{Path: cleanLocation(location), Err: err}
		}
		innerName := stripCompressionExtension(filename, ".bz2", ".bzip2")
		return s.scanFile(joinLocation(location, innerName), innerName, "application/octet-stream", decompressed, archiveDepth+1, state)
	default:
		return nil, nil
	}
}

func (s *Scanner) scanZIP(location string, data []byte, archiveDepth int, state *scanState) (*Finding, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		if finding, partialErr := s.scanPartialZIP(location, data, archiveDepth, state); finding != nil || partialErr != nil {
			return finding, partialErr
		}
		return nil, &ScanError{Path: cleanLocation(location), Err: fmt.Errorf("invalid ZIP archive: %w", err)}
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		entryLocation := joinLocation(location, file.Name)
		if file.Flags&1 != 0 {
			return nil, &ScanError{Path: entryLocation, Encrypted: true, Err: errors.New("encrypted archive entry cannot be inspected")}
		}
		if extension := s.blockedExtension(file.Name); extension != "" {
			return &Finding{Path: entryLocation, Detection: "blocked extension ." + extension}, nil
		}
		if err := s.beginArchiveFile(file.UncompressedSize64, state); err != nil {
			return nil, &ScanError{Path: entryLocation, Err: err}
		}
		entry, err := file.Open()
		if err != nil {
			return nil, &ScanError{Path: entryLocation, Err: fmt.Errorf("cannot open ZIP entry: %w", err)}
		}
		entryData, err := s.readArchiveEntry(entry, state)
		_ = entry.Close()
		if s.options.InspectSignatures {
			if signature := executableSignature(entryData); signature != "" {
				return &Finding{Path: entryLocation, Detection: signature}, nil
			}
		}
		if err != nil {
			return nil, &ScanError{Path: entryLocation, Err: err}
		}
		finding, scanErr := s.scanFile(entryLocation, file.Name, "application/octet-stream", entryData, archiveDepth, state)
		if finding != nil || scanErr != nil {
			return finding, scanErr
		}
	}
	return nil, nil
}

func (s *Scanner) scanPartialZIP(location string, data []byte, archiveDepth int, state *scanState) (*Finding, error) {
	const localHeaderBytes = 30
	if len(data) < localHeaderBytes || binary.LittleEndian.Uint32(data[:4]) != 0x04034b50 {
		return nil, nil
	}
	offset := 0
	for offset+localHeaderBytes <= len(data) && binary.LittleEndian.Uint32(data[offset:offset+4]) == 0x04034b50 {
		flags := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		method := binary.LittleEndian.Uint16(data[offset+8 : offset+10])
		compressedSize := uint64(binary.LittleEndian.Uint32(data[offset+18 : offset+22]))
		uncompressedSize := uint64(binary.LittleEndian.Uint32(data[offset+22 : offset+26]))
		nameLength := int(binary.LittleEndian.Uint16(data[offset+26 : offset+28]))
		extraLength := int(binary.LittleEndian.Uint16(data[offset+28 : offset+30]))
		dataStart := offset + localHeaderBytes + nameLength + extraLength
		if nameLength < 0 || extraLength < 0 || dataStart < offset || dataStart > len(data) {
			return nil, &ScanError{Path: cleanLocation(location), Err: errors.New("invalid partial ZIP entry header")}
		}
		name := string(data[offset+localHeaderBytes : offset+localHeaderBytes+nameLength])
		entryLocation := joinLocation(location, name)
		if flags&1 != 0 {
			return nil, &ScanError{Path: entryLocation, Encrypted: true, Err: errors.New("encrypted archive entry cannot be inspected")}
		}
		if extension := s.blockedExtension(name); extension != "" {
			return &Finding{Path: entryLocation, Detection: "blocked extension ." + extension}, nil
		}
		if err := s.beginArchiveFile(uncompressedSize, state); err != nil {
			return nil, &ScanError{Path: entryLocation, Err: err}
		}
		availableEnd := len(data)
		if compressedSize > 0 && compressedSize <= uint64(len(data)-dataStart) {
			availableEnd = dataStart + int(compressedSize)
		}
		compressed := data[dataStart:availableEnd]
		var entryReader io.ReadCloser
		switch method {
		case zip.Store:
			entryReader = io.NopCloser(bytes.NewReader(compressed))
		case zip.Deflate:
			entryReader = flate.NewReader(bytes.NewReader(compressed))
		default:
			return nil, &ScanError{Path: entryLocation, Err: fmt.Errorf("unsupported ZIP compression method %d", method)}
		}
		entryData, readErr := s.readArchiveEntry(entryReader, state)
		_ = entryReader.Close()
		if s.options.InspectSignatures {
			if signature := executableSignature(entryData); signature != "" {
				return &Finding{Path: entryLocation, Detection: signature}, nil
			}
		}
		if s.options.InspectArchives && archiveFormat(name, "application/octet-stream", entryData) != "" {
			if finding, _ := s.scanFile(entryLocation, name, "application/octet-stream", entryData, archiveDepth, state); finding != nil {
				return finding, nil
			}
		}
		if readErr != nil || compressedSize == 0 || compressedSize > uint64(len(data)-dataStart) || flags&8 != 0 {
			if readErr != nil {
				return nil, &ScanError{Path: entryLocation, Err: readErr}
			}
			return nil, &ScanError{Path: entryLocation, Err: errors.New("incomplete ZIP entry")}
		}
		offset = dataStart + int(compressedSize)
	}
	return nil, &ScanError{Path: cleanLocation(location), Err: errors.New("incomplete ZIP archive")}
}

func (s *Scanner) scanTAR(location string, reader io.Reader, archiveDepth int, state *scanState) (*Finding, error) {
	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, &ScanError{Path: cleanLocation(location), Err: fmt.Errorf("invalid TAR archive: %w", err)}
		}
		if !header.FileInfo().Mode().IsRegular() {
			continue
		}
		entryLocation := joinLocation(location, header.Name)
		if header.Size < 0 {
			return nil, &ScanError{Path: entryLocation, Err: errors.New("invalid negative archive entry size")}
		}
		if err := s.beginArchiveFile(uint64(header.Size), state); err != nil {
			return nil, &ScanError{Path: entryLocation, Err: err}
		}
		if extension := s.blockedExtension(header.Name); extension != "" {
			return &Finding{Path: entryLocation, Detection: "blocked extension ." + extension}, nil
		}
		entryData, err := s.readArchiveEntry(tarReader, state)
		if err != nil {
			return nil, &ScanError{Path: entryLocation, Err: err}
		}
		finding, scanErr := s.scanFile(entryLocation, header.Name, "application/octet-stream", entryData, archiveDepth, state)
		if finding != nil || scanErr != nil {
			return finding, scanErr
		}
	}
}

func (s *Scanner) readArchiveEntry(reader io.Reader, state *scanState) ([]byte, error) {
	remaining := s.options.MaxArchiveUncompressedBytes - state.archiveBytes
	if remaining <= 0 {
		return nil, errors.New("archive uncompressed-size limit exceeded")
	}
	limit := min(s.options.MaxAttachmentBytes, remaining)
	limited := &io.LimitedReader{R: reader, N: limit}
	data, err := io.ReadAll(limited)
	state.archiveBytes += int64(len(data))
	if err != nil {
		return data, err
	}
	var extra [1]byte
	if count, extraErr := reader.Read(extra[:]); count > 0 {
		if remaining <= s.options.MaxAttachmentBytes {
			return data, errors.New("archive uncompressed-size limit exceeded")
		}
		return data, errors.New("archive entry size limit exceeded")
	} else if extraErr != nil && extraErr != io.EOF {
		return data, extraErr
	}
	return data, nil
}

// beginArchiveFile uses declared sizes for early rejection only. The
// authoritative cumulative accounting is performed on bytes actually produced
// by readArchiveEntry, so understated archive metadata cannot bypass the limit.
func (s *Scanner) beginArchiveFile(declaredSize uint64, state *scanState) error {
	if state.archiveFiles >= s.options.MaxArchiveFiles {
		return errors.New("archive file-count limit exceeded")
	}
	if declaredSize > uint64(s.options.MaxAttachmentBytes) {
		return errors.New("archive entry size limit exceeded")
	}
	remaining := s.options.MaxArchiveUncompressedBytes - state.archiveBytes
	if remaining < 0 || declaredSize > uint64(remaining) {
		return errors.New("archive uncompressed-size limit exceeded")
	}
	state.archiveFiles++
	return nil
}

func (s *Scanner) blockedExtension(filename string) string {
	filename = strings.TrimRight(strings.ToLower(cleanName(filename)), ". ")
	parts := strings.Split(filename, ".")
	for _, extension := range parts[1:] {
		if _, blocked := s.blocked[extension]; blocked {
			return extension
		}
	}
	return ""
}

func attachmentFilename(contentDisposition, contentType string) string {
	for _, header := range []string{contentDisposition, contentType} {
		_, params, err := mime.ParseMediaType(header)
		if err != nil {
			continue
		}
		for _, key := range []string{"filename", "name"} {
			if value := decodeFilename(params[key]); value != "" {
				return value
			}
		}
	}
	return ""
}

func decodeFilename(value string) string {
	if decoded, err := new(mime.WordDecoder).DecodeHeader(value); err == nil {
		value = decoded
	}
	return cleanName(value)
}

func cleanName(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	value = path.Base(value)
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if value == "." || value == ".." || value == "/" || value == "" {
		return "unnamed"
	}
	if utf8.RuneCountInString(value) > 255 {
		value = string([]rune(value)[:255])
	}
	return value
}

func cleanLocation(value string) string {
	parts := strings.Split(strings.ReplaceAll(value, "\\", "/"), "/")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = cleanName(part); part != "unnamed" {
			cleaned = append(cleaned, part)
		}
	}
	if len(cleaned) == 0 {
		return "message"
	}
	return strings.Join(cleaned, "/")
}

func joinLocation(parent, child string) string {
	return cleanLocation(parent) + "/" + cleanName(child)
}

func replaceLocationBase(location, filename string) string {
	location = cleanLocation(location)
	if slash := strings.LastIndex(location, "/"); slash >= 0 {
		return location[:slash+1] + cleanName(filename)
	}
	return cleanName(filename)
}

func stripCompressionExtension(filename string, extensions ...string) string {
	filename = cleanName(filename)
	lower := strings.ToLower(filename)
	for _, extension := range extensions {
		if strings.HasSuffix(lower, extension) {
			name := strings.TrimSpace(filename[:len(filename)-len(extension)])
			if name != "" {
				return cleanName(name)
			}
		}
	}
	return "unnamed"
}

func archiveFormat(filename, mediaType string, data []byte) string {
	lowerName := strings.ToLower(filename)
	switch {
	case hasPrefix(data, []byte{'P', 'K', 3, 4}) || hasPrefix(data, []byte{'P', 'K', 5, 6}) || hasPrefix(data, []byte{'P', 'K', 7, 8}):
		return "zip"
	case hasPrefix(data, []byte{0x1f, 0x8b}):
		return "gzip"
	case hasPrefix(data, []byte("BZh")):
		return "bzip2"
	case len(data) >= 265 && string(data[257:262]) == "ustar":
		return "tar"
	case strings.HasSuffix(lowerName, ".zip") || mediaType == "application/zip":
		return "zip"
	case strings.HasSuffix(lowerName, ".tar") || mediaType == "application/x-tar":
		return "tar"
	case strings.HasSuffix(lowerName, ".gz") || strings.HasSuffix(lowerName, ".gzip") || mediaType == "application/gzip" || mediaType == "application/x-gzip":
		return "gzip"
	case strings.HasSuffix(lowerName, ".bz2") || strings.HasSuffix(lowerName, ".bzip2") || mediaType == "application/x-bzip2":
		return "bzip2"
	default:
		return ""
	}
}

func executableSignature(data []byte) string {
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		return "DOS/Windows executable signature"
	}
	if len(data) >= 4 && hasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
		return "ELF executable signature"
	}
	if len(data) >= 4 {
		magic := [4]byte{data[0], data[1], data[2], data[3]}
		switch magic {
		case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xce, 0xfa, 0xed, 0xfe},
			[4]byte{0xfe, 0xed, 0xfa, 0xcf}, [4]byte{0xcf, 0xfa, 0xed, 0xfe}:
			return "Mach-O executable signature"
		case [4]byte{0xca, 0xfe, 0xba, 0xbe}, [4]byte{0xbe, 0xba, 0xfe, 0xca},
			[4]byte{0xca, 0xfe, 0xba, 0xbf}, [4]byte{0xbf, 0xba, 0xfe, 0xca}:
			return "Mach-O universal executable signature"
		}
	}
	if interpreter := scriptInterpreter(data); interpreter != "" {
		return "executable script signature (" + interpreter + ")"
	}
	return ""
}

func scriptInterpreter(data []byte) string {
	if !hasPrefix(data, []byte("#!")) {
		return ""
	}
	line := string(data[2:min(len(data), 256)])
	if end := strings.IndexAny(line, "\r\n"); end >= 0 {
		line = line[:end]
	}
	fields := strings.Fields(strings.ToLower(line))
	if len(fields) == 0 {
		return ""
	}
	interpreter := path.Base(fields[0])
	if interpreter == "env" && len(fields) > 1 {
		interpreter = path.Base(fields[1])
	}
	dangerous := map[string]bool{
		"ash": true, "bash": true, "csh": true, "dash": true, "fish": true,
		"ksh": true, "node": true, "perl": true, "php": true, "pwsh": true,
		"python": true, "python2": true, "python3": true, "ruby": true,
		"sh": true, "tcsh": true, "zsh": true,
	}
	if dangerous[interpreter] {
		return interpreter
	}
	return ""
}

func decodeTransfer(encoding string, data []byte, limit int64) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(data)
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, reader)
	case "quoted-printable":
		reader = quotedprintable.NewReader(reader)
	case "", "7bit", "8bit", "binary":
	default:
		return nil, fmt.Errorf("unsupported content-transfer-encoding %q", encoding)
	}
	return readLimited(reader, limit)
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 1 {
		return nil, errors.New("invalid attachment size limit")
	}
	limited := &io.LimitedReader{R: reader, N: limit}
	data, err := io.ReadAll(limited)
	if err != nil {
		return data, err
	}
	var extra [1]byte
	if count, extraErr := reader.Read(extra[:]); count > 0 {
		return data, errors.New("attachment size limit exceeded")
	} else if extraErr != nil && extraErr != io.EOF {
		return data, extraErr
	}
	return data, nil
}

func hasPrefix(data, prefix []byte) bool {
	return len(data) >= len(prefix) && bytes.Equal(data[:len(prefix)], prefix)
}
