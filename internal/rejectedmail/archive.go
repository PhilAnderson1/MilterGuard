// Package rejectedmail stores bounded copies of rejected messages and removes
// them according to age and capacity limits.
package rejectedmail

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Directory     string
	Retention     time.Duration
	MaxMessages   int
	MaxTotalBytes int64
}

type Archive struct {
	mu      sync.Mutex
	opts    Options
	log     *slog.Logger
	now     func() time.Time
	files   []storedFile
	bytes   int64
	indexed bool
}

type storedFile struct {
	path       string
	size       int64
	modifiedAt time.Time
}

func New(opts Options, log *slog.Logger) *Archive {
	return &Archive{opts: opts, log: log, now: time.Now}
}

// Cleanup removes expired date trees hierarchically, then refreshes the
// capacity index and removes the oldest individual messages if required.
func (a *Archive) Cleanup() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(a.opts.Directory, 0750); err != nil {
		return err
	}
	cutoff := dateOnly(a.now().UTC().Add(-a.opts.Retention))
	removedTrees, err := a.removeExpiredDateTreesLocked(cutoff)
	if err != nil {
		return err
	}
	if err := a.indexLocked(); err != nil {
		return err
	}
	removedCapacity, err := a.enforceCapacityLocked(0, 0)
	if err != nil {
		return err
	}
	if a.log != nil {
		a.log.Debug("rejected mail archive cleaned", "expired_date_trees", removedTrees,
			"capacity_messages_removed", removedCapacity, "message_count", len(a.files), "total_bytes", a.bytes)
	}
	return nil
}

func (a *Archive) Save(message []byte) (string, error) {
	return a.save(message, 0)
}

// SaveWithRecordID saves a message using its rejection-history record ID.
func (a *Archive) SaveWithRecordID(message []byte, recordID uint64) (string, error) {
	if recordID == 0 {
		return "", fmt.Errorf("rejection record ID must be greater than zero")
	}
	return a.save(message, recordID)
}

func (a *Archive) save(message []byte, recordID uint64) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if int64(len(message)) > a.opts.MaxTotalBytes {
		return "", fmt.Errorf("message exceeds rejected mail archive byte limit")
	}
	if !a.indexed {
		if err := os.MkdirAll(a.opts.Directory, 0750); err != nil {
			return "", err
		}
		if err := a.indexLocked(); err != nil {
			return "", err
		}
	}
	if _, err := a.enforceCapacityLocked(int64(len(message)), 1); err != nil {
		return "", err
	}
	now := a.now().UTC()
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
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("rejected message archive file already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	temporary, err := os.CreateTemp(directory, ".milterguard-rejected-*")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0640); err != nil {
		cleanup()
		return "", err
	}
	if _, err := temporary.Write(message); err != nil {
		cleanup()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return "", err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return "", err
	}
	a.files = append(a.files, storedFile{path: path, size: int64(len(message)), modifiedAt: now})
	sortStoredFiles(a.files)
	a.bytes += int64(len(message))
	return path, nil
}

func (a *Archive) removeExpiredDateTreesLocked(cutoff time.Time) (int, error) {
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

func (a *Archive) indexLocked() error {
	a.files, a.bytes = nil, 0
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
		a.files = append(a.files, storedFile{path: path, size: info.Size(), modifiedAt: info.ModTime()})
		a.bytes += info.Size()
		return nil
	})
	if err != nil {
		return err
	}
	sortStoredFiles(a.files)
	a.indexed = true
	return nil
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

func (a *Archive) enforceCapacityLocked(incomingBytes int64, incomingMessages int) (int, error) {
	removed := 0
	for len(a.files) > 0 && (len(a.files)+incomingMessages > a.opts.MaxMessages || a.bytes+incomingBytes > a.opts.MaxTotalBytes) {
		oldest := a.files[0]
		if err := os.Remove(oldest.path); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		a.files = a.files[1:]
		a.bytes -= oldest.size
		removed++
		removeEmptyParents(filepath.Dir(oldest.path), a.opts.Directory)
	}
	return removed, nil
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
