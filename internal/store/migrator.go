package store

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migration represents a single database migration
type Migration struct {
	Version int
	Name    string
	UpSQL   string
}

// Migrator handles database schema migrations
type Migrator struct {
	db *sql.DB
}

// NewMigrator creates a new migrator instance
func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{db: db}
}

// getCurrentVersion returns the current schema version
func (m *Migrator) getCurrentVersion() (int, error) {
	// Check if schema_version table exists first
	var tableName string
	err := m.db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'",
	).Scan(&tableName)
	if err == sql.ErrNoRows {
		// Table doesn't exist, need to check legacy migrations
		return m.getLegacyVersion()
	}
	if err != nil {
		return 0, fmt.Errorf("failed to check schema_version table: %w", err)
	}

	var version int
	err = m.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to get current version: %w", err)
	}
	return version, nil
}

// getLegacyVersion checks if database was created before versioned migrations
func (m *Migrator) getLegacyVersion() (int, error) {
	// Check if any tables exist (indicating legacy schema)
	var count int
	err := m.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to check for existing tables: %w", err)
	}

	// If tables exist, assume version 1 is already applied
	// Create schema_version table and record version 1 for legacy databases
	if count > 0 {
		if _, err := m.db.Exec(`
			CREATE TABLE IF NOT EXISTS schema_version (
				version INTEGER PRIMARY KEY,
				applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				name TEXT NOT NULL
			);
			INSERT OR IGNORE INTO schema_version (version, name) VALUES (1, 'initial');
		`); err != nil {
			return 0, fmt.Errorf("failed to initialize schema_version for legacy database: %w", err)
		}
		return 1, nil
	}
	return 0, nil
}

// loadMigrations reads embedded migration files
func (m *Migrator) loadMigrations() ([]Migration, error) {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	migrationsMap := make(map[int]*Migration)

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		// Parse version from filename: NNN_name.up.sql
		parts := strings.SplitN(name, "_", 2)
		if len(parts) < 2 {
			continue
		}

		version, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		// Skip down migrations for now (we only apply up migrations)
		if strings.Contains(name, ".down.sql") {
			continue
		}

		content, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration %s: %w", name, err)
		}

		// Extract migration name from filename
		migName := strings.TrimSuffix(strings.TrimPrefix(strings.Join(parts[1:], "_"), "_"), ".up.sql")
		migName = strings.TrimSuffix(migName, ".up")

		migrationsMap[version] = &Migration{
			Version: version,
			Name:    migName,
			UpSQL:   string(content),
		}
	}

	// Convert map to sorted slice
	migrations := make([]Migration, 0, len(migrationsMap))
	for _, mig := range migrationsMap {
		migrations = append(migrations, *mig)
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// Up applies all pending migrations
func (m *Migrator) Up() error {
	currentVersion, err := m.getCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	if len(migrations) == 0 {
		return nil
	}

	// Apply each pending migration
	for _, mig := range migrations {
		if mig.Version <= currentVersion {
			continue
		}

		// Begin transaction
		tx, err := m.db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for migration %d: %w", mig.Version, err)
		}

		// Apply migration
		if _, err := tx.Exec(mig.UpSQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d (%s) failed: %w", mig.Version, mig.Name, err)
		}

		// Record migration in schema_version table
		// Note: The schema_version table is created by the first migration
		if _, err := tx.Exec(
			"INSERT OR REPLACE INTO schema_version (version, name) VALUES (?, ?)",
			mig.Version, mig.Name,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration %d: %w", mig.Version, err)
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %d: %w", mig.Version, err)
		}
	}

	return nil
}

// Version returns the current schema version
func (m *Migrator) Version() (int, error) {
	return m.getCurrentVersion()
}
