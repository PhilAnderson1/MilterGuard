package attachment

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
)

// Bound variable-length names, comments and extra fields independently of
// entry count. This is shared by all ZIPs in one message, including nested ZIPs.
const maxZIPMetadataBytes = 1 << 20

var (
	errArchiveFileCount = errors.New("archive file-count limit exceeded")
	errZIPMetadataLimit = errors.New("ZIP metadata size limit exceeded")
)

// admitZIPDirectory checks the metadata before archive/zip can allocate its
// File objects. Do not trust the advertised count or directory size: Go reads
// successive central headers until a different signature, and only compares
// the low 16 bits of the resulting count. Admission reserves all entries up
// front so nested archives share the budget with pending outer entries.
func (s *Scanner) admitZIPDirectory(data []byte, state *scanState) error {
	end, err := zipDirectoryEnd(data, state)
	if err != nil {
		return err
	}
	records := uint64(binary.LittleEndian.Uint16(data[end+10:]))
	size := uint64(binary.LittleEndian.Uint32(data[end+12:]))
	offset := uint64(binary.LittleEndian.Uint32(data[end+16:]))
	endOffset := end
	metadata := 22 + int(binary.LittleEndian.Uint16(data[end+20:]))
	// Match archive/zip's ZIP64 locator handling (including its 0xffff size
	// trigger), and validate fixed records before reading any fields.
	if records == 0xffff || size == 0xffff || offset == 0xffffffff {
		locator := end - 20
		if locator >= 0 && binary.LittleEndian.Uint32(data[locator:]) == 0x07064b50 &&
			binary.LittleEndian.Uint32(data[locator+4:]) == 0 && binary.LittleEndian.Uint32(data[locator+16:]) == 1 {
			position := binary.LittleEndian.Uint64(data[locator+8:])
			if len(data) < 56 || position > uint64(len(data)-56) {
				return zip.ErrFormat
			}
			p := int(position)
			if binary.LittleEndian.Uint32(data[p:]) != 0x06064b50 {
				return zip.ErrFormat
			}
			records = binary.LittleEndian.Uint64(data[p+32:])
			size = binary.LittleEndian.Uint64(data[p+40:])
			offset = binary.LittleEndian.Uint64(data[p+48:])
			endOffset = p
			metadata += 76
		}
	}
	remaining := s.options.MaxArchiveFiles - state.archiveFiles
	if remaining < 0 || records > uint64(remaining) {
		return errArchiveFileCount
	}
	if size > uint64(endOffset) || offset > uint64(len(data)) {
		return zip.ErrFormat
	}
	start := endOffset - int(size)
	if start >= len(data) {
		return zip.ErrFormat
	}
	if metadata > maxZIPMetadataBytes-state.zipMetadataBytes {
		return errZIPMetadataLimit
	}

	count, headerBytes, err := countZIPDirectory(data, start, remaining, maxZIPMetadataBytes-state.zipMetadataBytes-metadata, state)
	if err != nil {
		return err
	}
	// Go can prefer the advertised offset over the inferred offset when the
	// inferred base is positive (including some prefixed/self-extracting ZIPs).
	// Check both candidates, so differences in its header validation cannot
	// select an unbudgeted directory. Neither pass allocates record contents.
	if offset < uint64(start) {
		otherCount, otherBytes, err := countZIPDirectory(data, int(offset), remaining, maxZIPMetadataBytes-state.zipMetadataBytes-metadata, state)
		if err != nil {
			return err
		}
		count = max(count, otherCount)
		headerBytes = max(headerBytes, otherBytes)
	}
	// archive/zip may preallocate from the advertised count before reading
	// records. Do not admit an inflated count even if it fits the entry limit.
	if records > uint64(count) {
		return zip.ErrFormat
	}
	state.archiveFiles += count
	state.zipMetadataBytes += metadata + headerBytes
	return nil
}

type zipContextReaderAt struct {
	state *scanState
	data  *bytes.Reader
}

func (r zipContextReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	if err := r.state.check("ZIP archive"); err != nil {
		return 0, err
	}
	return r.data.ReadAt(p, offset)
}

func countZIPDirectory(data []byte, offset, entryLimit, byteLimit int, state *scanState) (int, int, error) {
	count, used := 0, 0
	for offset <= len(data)-46 && binary.LittleEndian.Uint32(data[offset:]) == 0x02014b50 {
		if err := state.check("ZIP directory"); err != nil {
			return 0, 0, err
		}
		if count >= entryLimit {
			return 0, 0, errArchiveFileCount
		}
		header := data[offset : offset+46]
		length := 46 + int(binary.LittleEndian.Uint16(header[28:])) + int(binary.LittleEndian.Uint16(header[30:])) + int(binary.LittleEndian.Uint16(header[32:]))
		if length > byteLimit-used {
			return 0, 0, errZIPMetadataLimit
		}
		if length > len(data)-offset {
			return 0, 0, zip.ErrFormat
		}
		count++
		used += length
		offset += length
	}
	return count, used, nil
}

// Use the same bounded, two-window end-record search as archive/zip, without
// copying the search windows. A truncated comment invalidates that window.
func zipDirectoryEnd(data []byte, state *scanState) (int, error) {
	for _, window := range []int{1024, 65 * 1024} {
		start := max(0, len(data)-window)
		for p := len(data) - 22; p >= start; p-- {
			if p%4096 == 0 {
				if err := state.check("ZIP directory"); err != nil {
					return 0, err
				}
			}
			if binary.LittleEndian.Uint32(data[p:]) != 0x06054b50 {
				continue
			}
			if int(binary.LittleEndian.Uint16(data[p+20:])) > len(data)-p-22 {
				break
			}
			return p, nil
		}
		if start == 0 {
			break
		}
	}
	return 0, zip.ErrFormat
}
