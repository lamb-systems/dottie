package state

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"database/sql"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

var migrationName = regexp.MustCompile(`^([0-9]{4})_[a-z0-9_]+\.sql$`)

type migration struct {
	version int
	name    string
	body    string
}

func loadMigrations(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	result := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := migrationName.FindStringSubmatch(entry.Name())
		if match == nil {
			return nil, fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		version, err := strconv.Atoi(match[1])
		if err != nil || version < 1 {
			return nil, fmt.Errorf("invalid migration version in %q", entry.Name())
		}
		body, err := fs.ReadFile(files, "migrations/"+entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		result = append(result, migration{version: version, name: entry.Name(), body: string(body)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].version < result[j].version })
	if len(result) == 0 {
		return nil, errors.New("no migrations found")
	}
	for i, item := range result {
		if item.version != i+1 {
			return nil, fmt.Errorf("migration sequence has a gap before version %d", item.version)
		}
	}
	return result, nil
}

func migrate(ctx context.Context, conn *sql.Conn, files fs.FS) error {
	migrations, err := loadMigrations(files)
	if err != nil {
		return err
	}
	version, err := currentSchemaVersion(ctx, conn)
	if err != nil {
		return err
	}
	latest := migrations[len(migrations)-1].version
	if version > latest {
		return fmt.Errorf("%w: database schema version %d is newer; this binary supports version %d", ErrUnsupportedSchema, version, latest)
	}
	for _, item := range migrations {
		if item.version <= version {
			continue
		}
		if err := applyMigration(ctx, conn, item, version); err != nil {
			return fmt.Errorf("apply migration %s: %w", item.name, err)
		}
		version = item.version
	}
	return nil
}

func ensureSupportedSchema(ctx context.Context, conn *sql.Conn, files fs.FS) error {
	migrations, err := loadMigrations(files)
	if err != nil {
		return err
	}
	version, err := currentSchemaVersion(ctx, conn)
	if err != nil {
		return err
	}
	latest := migrations[len(migrations)-1].version
	if version > latest {
		return fmt.Errorf("%w: database schema version %d is newer; this binary supports version %d", ErrUnsupportedSchema, version, latest)
	}
	return nil
}

func currentSchemaVersion(ctx context.Context, conn *sql.Conn) (int, error) {
	var exists int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'").Scan(&exists); err != nil {
		return 0, fmt.Errorf("inspect schema version: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}
	var version int
	if err := conn.QueryRowContext(ctx, "SELECT version FROM schema_version WHERE singleton = 1").Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

func applyMigration(ctx context.Context, conn *sql.Conn, item migration, previous int) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for _, statement := range splitStatements(item.body) {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if previous == 0 {
		_, err = tx.ExecContext(ctx, "INSERT INTO schema_version(singleton, version) VALUES (1, ?)", item.version)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE schema_version SET version = ? WHERE singleton = 1", item.version)
	}
	if err != nil {
		return fmt.Errorf("update schema version: %w", err)
	}
	if err := checkForeignKeys(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("restore foreign key enforcement: %w", err)
	}
	return nil
}

func checkForeignKeys(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return err
		}
		return fmt.Errorf("foreign key check failed: %v", values)
	}
	return rows.Err()
}

func splitStatements(body string) []string {
	parts := strings.Split(body, ";")
	statements := make([]string, 0, len(parts))
	for _, part := range parts {
		if statement := strings.TrimSpace(part); statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}
