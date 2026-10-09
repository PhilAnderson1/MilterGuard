// Package sqlitedb owns MilterGuard's SQLite connection infrastructure,
// including current-schema creation and validation, WAL configuration, busy
// retries, transactions, and checkpoints. Application queries live in
// repository implementations.
package sqlitedb
