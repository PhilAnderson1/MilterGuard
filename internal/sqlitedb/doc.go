// Package sqlitedb owns MilterGuard's SQLite connection infrastructure,
// including schema migration, WAL configuration, busy retries, transactions,
// and checkpoints. Application queries live in repository implementations.
package sqlitedb
