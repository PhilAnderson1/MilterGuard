// Package sqlstore owns MilterGuard's SQLite connection, schema lifecycle,
// transaction handling, and transient-lock retry policy.
package sqlstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
	lib "modernc.org/sqlite/lib"
)

const CurrentSchemaVersion = 1

var (
	//go:embed schema/*.sql
	schemaFiles embed.FS

	ErrIncompatibleDatabase = errors.New("incompatible SQLite database format")
)

type Options struct {
	BusyTimeout time.Duration
	BusyRetries int
	RetryDelay  time.Duration
	MaxOpen     int
}

func DefaultOptions() Options {
	return Options{
		BusyTimeout: 5 * time.Second,
		BusyRetries: 3,
		RetryDelay:  25 * time.Millisecond,
		MaxOpen:     8,
	}
}

// Store is the sole owner of a MilterGuard SQLite connection pool. Callers
// should use its methods instead of retaining the underlying *sql.DB.
type Store struct {
	db         *sql.DB
	retries    int
	retryDelay time.Duration
}

// Row defers execution until Scan so transient lock errors can be retried.
type Row struct {
	store *Store
	ctx   context.Context
	query string
	args  []any
}

func Open(ctx context.Context, path string, options Options) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("SQLite database path is empty")
	}
	if options.BusyTimeout <= 0 || options.BusyRetries < 0 || options.RetryDelay <= 0 || options.MaxOpen <= 0 {
		return nil, errors.New("invalid SQLite store options")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve SQLite database path: %w", err)
	}
	dsn := sqliteDSN(absolute, options.BusyTimeout)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(options.MaxOpen)
	db.SetMaxIdleConns(options.MaxOpen)
	store := &Store{db: db, retries: options.BusyRetries, retryDelay: options.RetryDelay}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to SQLite database: %w", err)
	}
	if err := os.Chmod(absolute, 0o640); err != nil {
		db.Close()
		return nil, fmt.Errorf("set SQLite database permissions: %w", err)
	}
	if err := store.prepareSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func sqliteDSN(path string, busyTimeout time.Duration) string {
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := u.Query()
	query.Set("_busy_timeout", strconv.FormatInt(busyTimeout.Milliseconds(), 10))
	query.Set("_journal_mode", "WAL")
	query.Set("_synchronous", "NORMAL")
	query.Set("_foreign_keys", "on")
	query.Set("_defensive", "true")
	query.Set("_dqs", "false")
	u.RawQuery = query.Encode()
	return u.String()
}

func (s *Store) prepareSchema(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read SQLite schema version: %w", err)
	}
	if version > CurrentSchemaVersion {
		return fmt.Errorf("%w: database version %d is newer than supported version %d", ErrIncompatibleDatabase, version, CurrentSchemaVersion)
	}
	if version == 0 {
		empty, err := s.databaseEmpty(ctx)
		if err != nil {
			return err
		}
		if !empty {
			return fmt.Errorf("%w: unversioned database is not empty", ErrIncompatibleDatabase)
		}
	}
	for next := version + 1; next <= CurrentSchemaVersion; next++ {
		if err := s.applyMigration(ctx, next); err != nil {
			return fmt.Errorf("apply SQLite schema migration %d: %w", next, err)
		}
	}
	return nil
}

func (s *Store) databaseEmpty(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema
		WHERE type IN ('table', 'index', 'trigger', 'view')
		AND name NOT LIKE 'sqlite_%'`).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("inspect SQLite schema: %w", err)
	}
	return count == 0, nil
}

func (s *Store) applyMigration(ctx context.Context, version int) error {
	name, script, err := migration(version)
	if err != nil {
		return err
	}
	return s.WithTx(ctx, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, script); err != nil {
			return fmt.Errorf("execute %s: %w", name, err)
		}
		_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version))
		return err
	})
}

func migration(version int) (string, string, error) {
	entries, err := fs.ReadDir(schemaFiles, "schema")
	if err != nil {
		return "", "", err
	}
	prefix := fmt.Sprintf("%03d_", version)
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) != 1 {
		return "", "", fmt.Errorf("expected one embedded migration for version %d, found %d", version, len(names))
	}
	content, err := schemaFiles.ReadFile("schema/" + names[0])
	return names[0], string(content), err
}

func (s *Store) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var result sql.Result
	err := s.retry(ctx, func() error {
		var err error
		result, err = s.db.ExecContext(ctx, query, args...)
		return err
	})
	return result, err
}

func (s *Store) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	var rows *sql.Rows
	err := s.retry(ctx, func() error {
		var err error
		rows, err = s.db.QueryContext(ctx, query, args...)
		return err
	})
	return rows, err
}

func (s *Store) QueryRow(ctx context.Context, query string, args ...any) *Row {
	return &Row{store: s, ctx: ctx, query: query, args: args}
}

func (r *Row) Scan(dest ...any) error {
	return r.store.retry(r.ctx, func() error {
		return r.store.db.QueryRowContext(r.ctx, r.query, r.args...).Scan(dest...)
	})
}

// WithTx retries the complete transaction after transient SQLite lock errors.
// fn must therefore be safe to invoke more than once and must not perform
// externally visible work unrelated to this database transaction.
func (s *Store) WithTx(ctx context.Context, options *sql.TxOptions, fn func(*sql.Tx) error) error {
	return s.retry(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, options)
		if err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			_ = tx.Rollback()
			return err
		}
		return tx.Commit()
	})
}

func (s *Store) retry(ctx context.Context, operation func() error) error {
	var err error
	for attempt := 0; attempt <= s.retries; attempt++ {
		if err = operation(); err == nil || !isBusy(err) || attempt == s.retries {
			return err
		}
		maximum := s.retryDelay << attempt
		delay := maximum/2 + time.Duration(rand.Int64N(max(int64(maximum/2), 1)))
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
	return err
}

func isBusy(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	code := sqliteErr.Code() & 0xff
	return code == lib.SQLITE_BUSY || code == lib.SQLITE_LOCKED
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
