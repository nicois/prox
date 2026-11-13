package store

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// Pair is a patched (IP, host) pair with its reason.
type Pair struct {
	IP     string
	Host   string
	Reason string
}

type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the patched-pair store at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS patched (
			ip           TEXT,
			host         TEXT,
			reason       TEXT,
			first        INTEGER,
			last_recheck INTEGER,
			attempts     INTEGER,
			PRIMARY KEY (ip, host)
		);`)
	return err
}

// MarkPatch records (or updates) a patched pair, bumping attempts on conflict.
func (s *Store) MarkPatch(ip, host, reason string, now time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO patched (ip, host, reason, first, last_recheck, attempts)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT(ip, host) DO UPDATE SET
			reason=excluded.reason,
			last_recheck=excluded.last_recheck,
			attempts=attempts+1`, ip, host, reason, now.UnixMilli(), now.UnixMilli())
	return err
}

// IsPatch reports whether the pair is currently patched.
func (s *Store) IsPatch(ip, host string) (bool, error) {
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM patched WHERE ip=? AND host=?`, ip, host).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil && exists == 1, err
}

// PatchDetail returns the stored patch reason for a pair.
func (s *Store) PatchDetail(ip, host string) (reason string, found bool, err error) {
	err = s.db.QueryRow(`SELECT reason FROM patched WHERE ip=? AND host=?`, ip, host).Scan(&reason)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return reason, err == nil, err
}

// Recheck returns pairs whose last_recheck is older than now - interval.
func (s *Store) Recheck(now time.Time, interval time.Duration) ([]Pair, error) {
	cutoff := now.Add(-interval).UnixMilli()
	rows, err := s.db.Query(`SELECT ip, host, reason FROM patched WHERE last_recheck<=?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pair
	for rows.Next() {
		var p Pair
		if err := rows.Scan(&p.IP, &p.Host, &p.Reason); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Unmark removes the pair from the store.
// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Unmark(ip, host string) error {
	_, err := s.db.Exec(`DELETE FROM patched WHERE ip=? AND host=?`, ip, host)
	return err
}
