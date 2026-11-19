package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"time"
)

var filenamePattern = regexp.MustCompile(`^[0-9]{3}_[a-z0-9_]+\.sql$`)

type migration struct {
	name     string
	checksum string
	sql      string
}

// Apply executes embedded migrations once, checking history and contents.
// Existing manually managed schemas require an explicit, independently reviewed baseline.
func Apply(ctx context.Context, db *sql.DB, files fs.FS, service, sentinel string) error {
	if service != "auth" && service != "user" && service != "content" && service != "media_processing" && service != "security_journal" {
		return errors.New("unsupported migration service")
	}

	if (service == "auth" && sentinel != "credentials") || (service == "user" && sentinel != "users") ||
		(service == "security_journal" && sentinel != "security_journal_events") || (service == "content" && sentinel != "content_posts") ||
		(service == "media_processing" && sentinel != "media_assets") {
		return errors.New("invalid migration sentinel")
	}

	items, err := readMigrations(files)

	if err != nil {
		return err
	}

	conn, err := db.Conn(ctx)

	if err != nil {
		return fmt.Errorf("open migration connection: %w", err)
	}

	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext('mtls:migrations'))`); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}

	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock(hashtext('mtls:migrations'))`)
	}()

	const createHistory = `CREATE TABLE IF NOT EXISTS mtls_schema_migrations (
		service TEXT NOT NULL,
		name TEXT NOT NULL,
		checksum TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (service, name)
	)`

	if _, err := conn.ExecContext(ctx, createHistory); err != nil {
		return fmt.Errorf("create migration history: %w", err)
	}

	applied, err := readHistory(ctx, conn, service)

	if err != nil {
		return err
	}

	var existing bool

	if err := conn.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, sentinel).Scan(&existing); err != nil {
		return fmt.Errorf("check existing schema: %w", err)
	}

	if len(applied) == 0 && existing {
		return errors.New("existing schema has no migration history; verify and baseline it before continuing")
	}

	if len(applied) > 0 && !existing {
		return errors.New("migration history exists but the service schema is missing")
	}

	known := make(map[string]string, len(items))

	for _, item := range items {
		known[item.name] = item.checksum
	}

	for name, checksum := range applied {
		if known[name] != checksum {
			return fmt.Errorf("migration history mismatch for %s", name)
		}
	}

	missing := false
	for _, item := range items {
		if _, ok := applied[item.name]; !ok {
			missing = true
		} else if missing {
			return fmt.Errorf("migration history has a gap before %s", item.name)
		}
	}

	for _, item := range items {
		if _, ok := applied[item.name]; ok {
			continue
		}

		if err := applyOne(ctx, conn, service, item); err != nil {
			return err
		}
	}

	return nil
}

func readMigrations(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, ".")

	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	var result []migration
	versions := make(map[string]struct{})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		if !filenamePattern.MatchString(entry.Name()) {
			return nil, fmt.Errorf("invalid migration filename: %s", entry.Name())
		}

		version := entry.Name()[:3]

		if _, exists := versions[version]; exists {
			return nil, fmt.Errorf("duplicate migration version: %s", version)
		}

		versions[version] = struct{}{}
		data, err := fs.ReadFile(files, entry.Name())

		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		hash := sha256.Sum256(data)
		result = append(result, migration{name: entry.Name(), checksum: hex.EncodeToString(hash[:]), sql: string(data)})
	}

	if len(result) == 0 {
		return nil, errors.New("no migrations found")
	}

	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result, nil
}

func readHistory(ctx context.Context, conn *sql.Conn, service string) (map[string]string, error) {
	rows, err := conn.QueryContext(ctx, `SELECT name, checksum FROM mtls_schema_migrations WHERE service = $1`, service)

	if err != nil {
		return nil, fmt.Errorf("read migration history: %w", err)
	}

	defer rows.Close()

	result := make(map[string]string)

	for rows.Next() {
		var name, checksum string

		if err := rows.Scan(&name, &checksum); err != nil {
			return nil, fmt.Errorf("scan migration history: %w", err)
		}

		result[name] = checksum
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate migration history: %w", err)
	}

	return result, nil
}

func applyOne(ctx context.Context, conn *sql.Conn, service string, item migration) error {
	tx, err := conn.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin migration %s: %w", item.name, err)
	}

	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, item.sql); err != nil {
		return fmt.Errorf("apply migration %s: %w", item.name, err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO mtls_schema_migrations (service, name, checksum) VALUES ($1, $2, $3)`, service, item.name, item.checksum); err != nil {
		return fmt.Errorf("record migration %s: %w", item.name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", item.name, err)
	}

	return nil
}
