package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type commandHistoryRepository struct {
	db *sqlitedb.Store
}

// NewCommandHistory binds interactive command history to the shared SQLite
// database.
func NewCommandHistory(db *sqlitedb.Store) stores.CommandHistoryRepository {
	return &commandHistoryRepository{db: db}
}

var _ stores.CommandHistoryRepository = (*commandHistoryRepository)(nil)

func (r *commandHistoryRepository) available() bool {
	return r != nil && r.db != nil
}

func (r *commandHistoryRepository) LoadCommandHistory(ctx context.Context) ([]string, error) {
	if !r.available() {
		return nil, fmt.Errorf("command history repository is unavailable")
	}
	rows, err := r.db.Query(ctx, `SELECT command FROM command_history ORDER BY position`)
	if err != nil {
		return nil, fmt.Errorf("load command history: %w", err)
	}
	defer rows.Close()
	commands := make([]string, 0, stores.CommandHistoryLimit)
	for rows.Next() {
		var command string
		if err := rows.Scan(&command); err != nil {
			return nil, fmt.Errorf("scan command history: %w", err)
		}
		commands = append(commands, command)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read command history: %w", err)
	}
	return commands, nil
}

func (r *commandHistoryRepository) SaveCommandHistory(ctx context.Context, commands []string) error {
	if !r.available() {
		return fmt.Errorf("command history repository is unavailable")
	}
	if len(commands) > stores.CommandHistoryLimit {
		commands = commands[len(commands)-stores.CommandHistoryLimit:]
	}
	return r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM command_history`); err != nil {
			return fmt.Errorf("clear command history: %w", err)
		}
		for index, command := range commands {
			if command == "" {
				return fmt.Errorf("command history contains an empty command")
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO command_history (position, command) VALUES (?, ?)`, index+1, command); err != nil {
				return fmt.Errorf("save command history entry: %w", err)
			}
		}
		return nil
	})
}
