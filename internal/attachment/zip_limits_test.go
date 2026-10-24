package attachment

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// Directory entries need no local data to be inspected. Build central records
// directly so tests can forge counts and offsets independently of the writer.
func directoryZIP(entries, commentBytes int, zip64 bool) []byte {
	recordBytes := 48 + commentBytes
	data := make([]byte, entries*recordBytes)
	for i := 0; i < entries; i++ {
		header := data[i*recordBytes:]
		binary.LittleEndian.PutUint32(header, 0x02014b50)
		binary.LittleEndian.PutUint16(header[28:], 2)
		binary.LittleEndian.PutUint16(header[32:], uint16(commentBytes))
		copy(header[46:], "a/")
	}
	end := make([]byte, 22)
	binary.LittleEndian.PutUint32(end, 0x06054b50)
	binary.LittleEndian.PutUint16(end[8:], uint16(entries))
	binary.LittleEndian.PutUint16(end[10:], uint16(entries))
	binary.LittleEndian.PutUint32(end[12:], uint32(len(data)))
	if zip64 {
		end64 := make([]byte, 56)
		binary.LittleEndian.PutUint32(end64, 0x06064b50)
		binary.LittleEndian.PutUint64(end64[4:], 44)
		binary.LittleEndian.PutUint64(end64[24:], uint64(entries))
		binary.LittleEndian.PutUint64(end64[32:], uint64(entries))
		binary.LittleEndian.PutUint64(end64[40:], uint64(len(data)))
		locator := make([]byte, 20)
		binary.LittleEndian.PutUint32(locator, 0x07064b50)
		binary.LittleEndian.PutUint64(locator[8:], uint64(len(data)))
		binary.LittleEndian.PutUint32(locator[16:], 1)
		data = append(data, end64...)
		data = append(data, locator...)
		binary.LittleEndian.PutUint16(end[8:], 0xffff)
		binary.LittleEndian.PutUint16(end[10:], 0xffff)
	}
	return append(data, end...)
}

func TestZIPDirectoriesConsumeEntryBudget(t *testing.T) {
	for _, zip64 := range []bool{false, true} {
		s := testScanner()
		s.options.MaxArchiveFiles = 2
		state := &scanState{}
		finding, err := s.scanZIP("dirs.zip", directoryZIP(2, 0, zip64), 1, state)
		if finding != nil || err != nil || state.archiveFiles != 2 {
			t.Fatalf("zip64=%v finding=%v err=%v count=%d", zip64, finding, err, state.archiveFiles)
		}
		if _, err := s.scanZIP("dirs.zip", directoryZIP(3, 0, zip64), 1, &scanState{}); !errors.Is(err, errArchiveFileCount) {
			t.Fatalf("zip64=%v excess directories: %v", zip64, err)
		}
	}
}

func TestZIPForgedCountsAndOffsetsCannotBypassAdmission(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"wrapped count", directoryZIP(65536, 0, false)},
		{"inflated count", directoryZIP(1, 0, false)},
		{"understated directory size", directoryZIP(101, 0, false)},
		{"inflated ZIP64 count", directoryZIP(1, 0, true)},
	}
	// An advertised zero count wraps correctly for 65536 actual entries.
	binary.LittleEndian.PutUint16(tests[1].data[len(tests[1].data)-12:], 100)
	// Go may select the advertised offset zero rather than inferred last entry.
	data := tests[2].data
	binary.LittleEndian.PutUint16(data[len(data)-12:], 1)
	binary.LittleEndian.PutUint32(data[len(data)-10:], 48)
	binary.LittleEndian.PutUint64(tests[3].data[48+32:], ^uint64(0))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testScanner()
			s.options.MaxArchiveFiles = 100
			if err := s.admitZIPDirectory(tt.data, &scanState{}); err == nil {
				t.Fatal("forged metadata admitted")
			}
		})
	}
}

func TestZIPMetadataBudgetIsCumulative(t *testing.T) {
	s := testScanner()
	s.options.MaxArchiveFiles = 100
	state := &scanState{}
	data := directoryZIP(8, 65535, false)
	if _, err := s.scanZIP("first.zip", data, 1, state); err != nil {
		t.Fatal(err)
	}
	if _, err := s.scanZIP("second.zip", data, 1, state); !errors.Is(err, errZIPMetadataLimit) {
		t.Fatalf("cumulative metadata limit not enforced: %v", err)
	}
	if _, err := s.scanZIP("large.zip", directoryZIP(17, 65535, false), 1, &scanState{}); !errors.Is(err, errZIPMetadataLimit) {
		t.Fatalf("single directory metadata limit not enforced: %v", err)
	}
}

func TestZIPNestedDirectoriesShareEntryBudget(t *testing.T) {
	inner := directoryZIP(2, 0, false)
	outer := makeZIP(t, map[string][]byte{"one.zip": inner, "two.zip": inner})
	s := testScanner()
	s.options.MaxArchiveFiles = 5 // Two outer files and four inner directories.
	if _, err := s.scanZIP("outer.zip", outer, 1, &scanState{}); !errors.Is(err, errArchiveFileCount) {
		t.Fatalf("nested directories escaped shared budget: %v", err)
	}
	s.options.MaxArchiveFiles = 6
	if _, err := s.scanZIP("outer.zip", outer, 1, &scanState{}); err != nil {
		t.Fatal(err)
	}
}

func TestZIPAdmissionSupportsPrefixedArchives(t *testing.T) {
	data := append([]byte("self-extracting-prefix"), directoryZIP(2, 0, false)...)
	if _, err := testScanner().scanZIP("prefixed.zip", data, 1, &scanState{}); err != nil {
		t.Fatal(err)
	}
	// Real local file offsets must also survive a prefix, not just directories.
	data = append([]byte("prefix"), makeZIP(t, map[string][]byte{"safe.txt": []byte("safe")})...)
	if _, err := testScanner().scanZIP("prefixed.zip", data, 1, &scanState{}); err != nil {
		t.Fatal(err)
	}
}

func TestZIPAdmissionCancellationAndTruncation(t *testing.T) {
	data := directoryZIP(2, 0, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := testScanner().scanZIP("cancelled.zip", data, 1, &scanState{ctx: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	for length := 0; length < len(data); length++ {
		if err := testScanner().admitZIPDirectory(data[:length], &scanState{}); err == nil {
			t.Fatalf("truncated ZIP admitted at %d", length)
		}
	}
}

func TestZIPEntryFloodDoesNotAllocateFileList(t *testing.T) {
	data := directoryZIP(65536, 0, false)
	s := testScanner()
	s.options.MaxArchiveFiles = 100
	allocations := testing.AllocsPerRun(3, func() {
		if _, err := s.scanZIP("flood.zip", data, 1, &scanState{}); !errors.Is(err, errArchiveFileCount) {
			t.Fatalf("flood error: %v", err)
		}
	})
	if allocations > 100 {
		t.Fatalf("flood allocated file objects before rejection: %g allocations", allocations)
	}
}

func FuzzZIPDirectoryAdmission(f *testing.F) {
	f.Add(directoryZIP(2, 0, false))
	f.Add(directoryZIP(2, 0, true))
	f.Add(append([]byte("prefix"), directoryZIP(2, 0, false)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		s := testScanner()
		state := &scanState{}
		if err := s.admitZIPDirectory(data, state); err != nil {
			return
		}
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err == nil && len(reader.File) > state.archiveFiles {
			t.Fatalf("stdlib parsed %d entries after admission reserved %d", len(reader.File), state.archiveFiles)
		}
	})
}
