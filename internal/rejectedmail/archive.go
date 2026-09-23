package rejectedmail

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Options struct {
	Directory     string
	Retention     time.Duration
	MaxTotalBytes int64
}

type Archive struct {
	opts Options
	log  *slog.Logger
	now  func() time.Time
}

// StoredMessage contains an archived message and its authoritative filesystem
// path. Callers must not reconstruct the archive's date-based layout.
type StoredMessage struct {
	Contents []byte
	Path     string
}

type storedFile struct {
	path       string
	size       int64
	modifiedAt time.Time
}

// New describes an archive rooted at one configured directory. The archive
// root is created when cleanup first runs or when the first message is saved.
func New(opts Options, log *slog.Logger) *Archive {
	return &Archive{opts: opts, log: log, now: time.Now}
}

// Cleanup removes expired date directories, then deletes the oldest remaining
// messages only when the archive exceeds its target maximum size.
func (a *Archive) Cleanup() error {
	if err := os.MkdirAll(a.opts.Directory, 0750); err != nil {
		return err
	}
	cutoff := dateOnly(a.now().UTC().Add(-a.opts.Retention))
	removedTrees, err := a.removeExpiredDateTrees(cutoff)
	if err != nil {
		return err
	}
	totalBytes, err := a.archiveSize()
	if err != nil {
		return err
	}
	removedCapacity := 0
	if totalBytes > a.opts.MaxTotalBytes {
		files, indexedBytes, err := a.indexFiles()
		if err != nil {
			return err
		}
		totalBytes = indexedBytes
		sortStoredFiles(files)
		for _, file := range files {
			if totalBytes <= a.opts.MaxTotalBytes {
				break
			}
			if err := os.Remove(file.path); err != nil {
				return err
			}
			totalBytes -= file.size
			removedCapacity++
			removeEmptyParents(filepath.Dir(file.path), a.opts.Directory)
		}
	}
	if a.log != nil {
		a.log.Debug("rejected mail archive cleaned", "expired_date_trees", removedTrees,
			"capacity_messages_removed", removedCapacity, "total_bytes", totalBytes)
	}
	return nil
}

func (a *Archive) Save(message []byte) (string, error) {
	return a.save(message, 0)
}

// SaveWithRecordIDAt writes a message beneath the rejection record's UTC date
// path using its ID as the filename, allowing retrieval to derive the exact
// location from the database row.
func (a *Archive) SaveWithRecordIDAt(message []byte, recordID uint64, rejectedAt time.Time) (string, error) {
	if recordID == 0 {
		return "", fmt.Errorf("rejection record ID must be greater than zero")
	}
	if rejectedAt.IsZero() {
		return "", fmt.Errorf("rejection time must be set")
	}
	return a.saveAt(message, recordID, rejectedAt.UTC())
}

// ReadWithRecordID reads the exact message associated with a rejection record.
// Its path components are derived exclusively from typed database values.
func (a *Archive) ReadWithRecordID(recordID uint64, rejectedAt time.Time, maxBytes int64) (StoredMessage, error) {
	if a == nil || recordID == 0 || rejectedAt.IsZero() {
		return StoredMessage{}, fs.ErrNotExist
	}
	if maxBytes < 1 {
		return StoredMessage{}, fmt.Errorf("saved message read limit must be positive")
	}
	rejectedAt = rejectedAt.UTC()
	path := filepath.Join(a.opts.Directory, rejectedAt.Format("2006"), rejectedAt.Format("01"), rejectedAt.Format("02"), strconv.FormatUint(recordID, 10)+".eml")
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return StoredMessage{}, fs.ErrNotExist
		}
		return StoredMessage{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return StoredMessage{}, err
	}
	if !info.Mode().IsRegular() {
		return StoredMessage{}, fmt.Errorf("saved message is not a regular file")
	}
	if info.Size() > maxBytes {
		return StoredMessage{}, fmt.Errorf("saved message exceeds read limit")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return StoredMessage{}, err
	}
	if int64(len(contents)) > maxBytes {
		return StoredMessage{}, fmt.Errorf("saved message exceeds read limit")
	}
	return StoredMessage{Contents: contents, Path: path}, nil
}

func (a *Archive) save(message []byte, recordID uint64) (string, error) {
	return a.saveAt(message, recordID, a.now().UTC())
}

func (a *Archive) saveAt(message []byte, recordID uint64, now time.Time) (string, error) {
	if int64(len(message)) > a.opts.MaxTotalBytes {
		return "", fmt.Errorf("message exceeds rejected mail archive byte limit")
	}
	directory := filepath.Join(a.opts.Directory, now.Format("2006"), now.Format("01"), now.Format("02"))
	if err := os.MkdirAll(directory, 0750); err != nil {
		return "", err
	}
	var name string
	if recordID != 0 {
		name = strconv.FormatUint(recordID, 10) + ".eml"
	} else {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", err
		}
		name = now.Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random[:]) + ".eml"
	}
	path := filepath.Join(directory, name)
	file, err := openArchiveFile(path, directory)
	if err != nil {
		if os.IsExist(err) {
			return "", fmt.Errorf("rejected message archive file already exists: %s", path)
		}
		return "", err
	}
	if _, err := file.Write(message); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func openArchiveFile(path, directory string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return file, err
	}
	// Capacity cleanup may remove an empty date directory after saveAt's
	// initial MkdirAll but before file creation. Recreate that already-derived
	// directory and retry once without weakening exclusive creation.
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
}

func (a *Archive) removeExpiredDateTrees(cutoff time.Time) (int, error) {
	years, err := os.ReadDir(a.opts.Directory)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, yearEntry := range years {
		year, ok := dateDirectoryNumber(yearEntry, 4, 1, 9999)
		if !ok {
			continue
		}
		yearPath := filepath.Join(a.opts.Directory, yearEntry.Name())
		if !time.Date(year+1, 1, 1, 0, 0, 0, 0, time.UTC).After(cutoff) {
			if err := os.RemoveAll(yearPath); err != nil {
				return removed, err
			}
			removed++
			continue
		}
		months, err := os.ReadDir(yearPath)
		if err != nil {
			return removed, err
		}
		for _, monthEntry := range months {
			monthNumber, ok := dateDirectoryNumber(monthEntry, 2, 1, 12)
			if !ok {
				continue
			}
			month := time.Month(monthNumber)
			monthPath := filepath.Join(yearPath, monthEntry.Name())
			if !time.Date(year, month+1, 1, 0, 0, 0, 0, time.UTC).After(cutoff) {
				if err := os.RemoveAll(monthPath); err != nil {
					return removed, err
				}
				removed++
				continue
			}
			days, err := os.ReadDir(monthPath)
			if err != nil {
				return removed, err
			}
			for _, dayEntry := range days {
				day, ok := validDayDirectory(dayEntry, year, month)
				if !ok || !day.Before(cutoff) {
					continue
				}
				if err := os.RemoveAll(filepath.Join(monthPath, dayEntry.Name())); err != nil {
					return removed, err
				}
				removed++
			}
			removeIfEmpty(monthPath)
		}
		removeIfEmpty(yearPath)
	}
	return removed, nil
}

func (a *Archive) archiveSize() (int64, error) {
	var total int64
	err := filepath.WalkDir(a.opts.Directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".eml") || !a.validMessagePath(path) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func (a *Archive) indexFiles() ([]storedFile, int64, error) {
	var files []storedFile
	var total int64
	err := filepath.WalkDir(a.opts.Directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".eml") || !a.validMessagePath(path) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		files = append(files, storedFile{path: path, size: info.Size(), modifiedAt: info.ModTime()})
		total += info.Size()
		return nil
	})
	return files, total, err
}

func sortStoredFiles(files []storedFile) {
	sort.Slice(files, func(i, j int) bool {
		if files[i].modifiedAt.Equal(files[j].modifiedAt) {
			return files[i].path < files[j].path
		}
		return files[i].modifiedAt.Before(files[j].modifiedAt)
	})
}

func (a *Archive) validMessagePath(path string) bool {
	relative, err := filepath.Rel(a.opts.Directory, path)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) != 4 || len(parts[0]) != 4 || len(parts[1]) != 2 || len(parts[2]) != 2 {
		return false
	}
	year, yearErr := strconv.Atoi(parts[0])
	month, monthErr := strconv.Atoi(parts[1])
	day, dayErr := strconv.Atoi(parts[2])
	if yearErr != nil || monthErr != nil || dayErr != nil || month < 1 || month > 12 {
		return false
	}
	date := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	return date.Year() == year && int(date.Month()) == month && date.Day() == day
}

func dateOnly(value time.Time) time.Time {
	year, month, day := value.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func dateDirectoryNumber(entry fs.DirEntry, width, minimum, maximum int) (int, bool) {
	if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || len(entry.Name()) != width {
		return 0, false
	}
	value, err := strconv.Atoi(entry.Name())
	return value, err == nil && value >= minimum && value <= maximum
}

func validDayDirectory(entry fs.DirEntry, year int, month time.Month) (time.Time, bool) {
	day, ok := dateDirectoryNumber(entry, 2, 1, 31)
	if !ok {
		return time.Time{}, false
	}
	value := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	return value, value.Year() == year && value.Month() == month && value.Day() == day
}

func removeIfEmpty(path string) {
	entries, err := os.ReadDir(path)
	if err == nil && len(entries) == 0 {
		_ = os.Remove(path)
	}
}

func removeEmptyParents(path, root string) {
	for path != root && strings.HasPrefix(path, root+string(os.PathSeparator)) {
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			return
		}
		if err := os.Remove(path); err != nil {
			return
		}
		path = filepath.Dir(path)
	}
}
