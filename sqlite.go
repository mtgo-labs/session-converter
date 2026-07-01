package tgconv

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// SQLiteFormat identifies which library produced a SQLite session file.
type SQLiteFormat string

const (
	SQLiteTelethon SQLiteFormat = "telethon"
	SQLitePyrogram SQLiteFormat = "pyrogram"
)

// ReadSQLite auto-detects whether a SQLite file is a Telethon or Pyrogram
// session file and extracts the session data.
func ReadSQLite(path string) (*Session, SQLiteFormat, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, "", fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()

	format, err := detectSQLiteFormat(db)
	if err != nil {
		return nil, "", err
	}

	switch format {
	case SQLiteTelethon:
		s, err := readTelethonDB(db)
		return s, SQLiteTelethon, err
	case SQLitePyrogram:
		s, err := readPyrogramDB(db)
		return s, SQLitePyrogram, err
	default:
		return nil, "", fmt.Errorf("unrecognized sqlite session format")
	}
}

// detectSQLiteFormat examines the table names to identify the library.
func detectSQLiteFormat(db *sql.DB) (SQLiteFormat, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return "", fmt.Errorf("query tables: %w", err)
	}
	defer rows.Close()

	tables := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return "", err
		}
		tables[name] = true
	}

	if tables["sessions"] && tables["entities"] && tables["version"] {
		return SQLiteTelethon, nil
	}
	if tables["sessions"] && tables["peers"] && tables["version"] {
		return SQLitePyrogram, nil
	}

	return "", fmt.Errorf("unrecognized sqlite schema (tables: %v)", tables)
}

// ReadTelethonSQLite reads session data from a Telethon .session SQLite file.
func ReadTelethonSQLite(path string) (*Session, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	return readTelethonDB(db)
}

func readTelethonDB(db *sql.DB) (*Session, error) {
	var s Session
	var authKey []byte

	err := db.QueryRow(
		`SELECT dc_id, server_address, port, auth_key FROM sessions LIMIT 1`,
	).Scan(&s.DCID, &s.ServerAddress, &s.Port, &authKey)
	if err != nil {
		return nil, fmt.Errorf("telethon sqlite: query sessions: %w", err)
	}

	if len(authKey) != 256 {
		return nil, fmt.Errorf("telethon sqlite: auth_key must be 256 bytes, got %d", len(authKey))
	}
	s.AuthKey = authKey

	// Try to extract user ID from entities table.
	var userID int64
	err = db.QueryRow(
		`SELECT id FROM entities WHERE id != 0 ORDER BY date DESC LIMIT 1`,
	).Scan(&userID)
	if err == nil {
		s.UserID = userID
	}

	s.fillDefaults()
	return &s, nil
}

// ReadPyrogramSQLite reads session data from a Pyrogram .session SQLite file.
func ReadPyrogramSQLite(path string) (*Session, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	return readPyrogramDB(db)
}

func readPyrogramDB(db *sql.DB) (*Session, error) {
	var s Session
	var authKey []byte
	var testMode, isBot int
	var userID int64
	var apiID sql.NullInt32

	// Check if api_id column exists (newer schema).
	var hasAPIID bool
	rows, err := db.Query(`PRAGMA table_info(sessions)`)
	if err != nil {
		return nil, fmt.Errorf("pyrogram sqlite: pragma: %w", err)
	}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return nil, err
		}
		if name == "api_id" {
			hasAPIID = true
		}
	}
	rows.Close()

	if hasAPIID {
		err = db.QueryRow(
			`SELECT dc_id, api_id, test_mode, auth_key, user_id, is_bot FROM sessions LIMIT 1`,
		).Scan(&s.DCID, &apiID, &testMode, &authKey, &userID, &isBot)
	} else {
		err = db.QueryRow(
			`SELECT dc_id, test_mode, auth_key, user_id, is_bot FROM sessions LIMIT 1`,
		).Scan(&s.DCID, &testMode, &authKey, &userID, &isBot)
	}
	if err != nil {
		return nil, fmt.Errorf("pyrogram sqlite: query sessions: %w", err)
	}

	if len(authKey) != 256 {
		return nil, fmt.Errorf("pyrogram sqlite: auth_key must be 256 bytes, got %d", len(authKey))
	}

	s.AuthKey = authKey
	s.TestMode = testMode != 0
	s.UserID = userID
	s.IsBot = isBot != 0
	if apiID.Valid {
		s.AppID = apiID.Int32
	}

	s.fillDefaults()
	return &s, nil
}
