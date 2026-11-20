// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package store keeps the relay's state in one SQLite file: registered servers, registration links, device handles,
// the send log and daily usage. Times are Unix milliseconds. Secrets are stored only as SHA-256 hashes.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrLimit is returned when an email already has the most servers it may register.
var ErrLimit = errors.New("store: server limit reached")

// Instance statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusBanned    = "banned"
)

// Store is the relay database. One connection: SQLite serialises writes anyway, and this keeps transactions simple.
type Store struct {
	db *sql.DB
}

var migrations = []string{
	`CREATE TABLE instances (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		email TEXT NOT NULL,
		url TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'banned')),
		secret_hash BLOB NOT NULL,
		domain_verified_at INTEGER NOT NULL DEFAULT 0,
		domain_checked_at INTEGER NOT NULL DEFAULT 0,
		quota_per_minute INTEGER NOT NULL DEFAULT 0,
		quota_per_day INTEGER NOT NULL DEFAULT 0,
		terms_version INTEGER NOT NULL,
		terms_accepted_at INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		created_ip TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX idx_instances_email ON instances (email);
	CREATE TABLE email_tokens (
		token_hash BLOB PRIMARY KEY,
		purpose TEXT NOT NULL,
		email TEXT NOT NULL,
		payload TEXT NOT NULL DEFAULT '{}',
		expires_at INTEGER NOT NULL,
		used_at INTEGER
	);
	CREATE TABLE banned_emails (
		email_hash BLOB PRIMARY KEY,
		banned_at INTEGER NOT NULL
	);
	CREATE TABLE handles (
		handle TEXT PRIMARY KEY,
		secret_hash BLOB NOT NULL,
		instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
		platform TEXT NOT NULL CHECK (platform IN ('ios', 'android')),
		fcm_token TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		refreshed_at INTEGER NOT NULL,
		last_sent_at INTEGER NOT NULL DEFAULT 0,
		revoked_at INTEGER NOT NULL DEFAULT 0,
		UNIQUE (instance_id, fcm_token)
	);
	CREATE TABLE send_log (
		message_id TEXT PRIMARY KEY,
		instance_id TEXT NOT NULL,
		handle TEXT NOT NULL,
		at INTEGER NOT NULL,
		size INTEGER NOT NULL,
		ciphertext_sha256 BLOB NOT NULL,
		status TEXT NOT NULL
	);
	CREATE INDEX idx_send_log_handle ON send_log (handle, at);
	CREATE INDEX idx_send_log_at ON send_log (at);
	CREATE TABLE usage_daily (
		instance_id TEXT NOT NULL,
		day TEXT NOT NULL,
		sent INTEGER NOT NULL DEFAULT 0,
		rate_limited INTEGER NOT NULL DEFAULT 0,
		invalid_handle INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (instance_id, day)
	);`,
	// client_id is the sender's idempotency key; status is pending until the provider answers, then ok or failed.
	`ALTER TABLE send_log ADD COLUMN client_id TEXT;
	CREATE UNIQUE INDEX idx_send_log_client ON send_log (instance_id, client_id) WHERE client_id IS NOT NULL;`,
	// Keeps the search for abandoned pending sends cheap enough to run on every reservation.
	`CREATE INDEX idx_send_log_pending ON send_log (at) WHERE status = 'pending';`,
	// iOS goes straight to APNs: fcm_token becomes token, and an iOS handle names its APNs environment. Live iOS
	// handles from before hold FCM tokens APNs cannot use, so they are revoked and the app registers again.
	`CREATE TABLE handles_new (
		handle TEXT PRIMARY KEY,
		secret_hash BLOB NOT NULL,
		instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
		platform TEXT NOT NULL CHECK (platform IN ('ios', 'android')),
		token TEXT NOT NULL,
		apns_env TEXT,
		created_at INTEGER NOT NULL,
		refreshed_at INTEGER NOT NULL,
		last_sent_at INTEGER NOT NULL DEFAULT 0,
		revoked_at INTEGER NOT NULL DEFAULT 0,
		UNIQUE (instance_id, token),
		CHECK ((platform = 'android' AND apns_env IS NULL) OR (platform = 'ios' AND
			(coalesce(apns_env, '') IN ('sandbox', 'production') OR (apns_env IS NULL AND revoked_at <> 0))))
	);
	INSERT INTO handles_new (handle, secret_hash, instance_id, platform, token, apns_env, created_at, refreshed_at,
		last_sent_at, revoked_at)
	SELECT handle, secret_hash, instance_id, platform, fcm_token, NULL, created_at, refreshed_at, last_sent_at,
		CASE WHEN platform = 'ios' AND revoked_at = 0 THEN CAST(strftime('%s', 'now') AS INTEGER) * 1000 ELSE revoked_at END
	FROM handles;
	DROP TABLE handles;
	ALTER TABLE handles_new RENAME TO handles;`,
}

// Open opens (creating if needed) the database at path and brings its schema up to date.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// DB is the underlying database, for tests and one-off repairs.
func (s *Store) DB() *sql.DB { return s.db }

// Backup writes a consistent copy of the database to path, which must not exist yet.
func (s *Store) Backup(ctx context.Context, path string) error {
	_, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Ms is t as Unix milliseconds.
func Ms(t time.Time) int64 { return t.UnixMilli() }

// Day is the UTC calendar day of t, the key of daily usage.
func Day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// ── Registration links ──────────────────────────────────────────────────────────────────────────

// CreateEmailToken stores a one-time link token by its hash.
func (s *Store) CreateEmailToken(ctx context.Context, hash []byte, purpose, email, payload string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO email_tokens (token_hash, purpose, email, payload, expires_at) VALUES (?, ?, ?, ?, ?)`,
		hash, purpose, email, payload, Ms(expires))
	return err
}

// ConsumeEmailToken marks an unused, unexpired token used and returns its email and payload. ErrNotFound otherwise.
func (s *Store) ConsumeEmailToken(ctx context.Context, hash []byte, purpose string, now time.Time) (email, payload string, err error) {
	err = s.db.QueryRowContext(ctx, `UPDATE email_tokens SET used_at = ?
		WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
		RETURNING email, payload`, Ms(now), hash, purpose, Ms(now)).Scan(&email, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return email, payload, err
}

// ── Instances ───────────────────────────────────────────────────────────────────────────────────

// Instance is one registered beacon-server.
type Instance struct {
	ID, Name, Email, URL, Status string
	SecretHash                   []byte
	DomainVerifiedAt             int64 // 0: not verified
	DomainCheckedAt              int64
	QuotaPerMinute, QuotaPerDay  int // 0: the tier default
	TermsVersion                 int
	TermsAcceptedAt, CreatedAt   int64
	CreatedIP                    string
}

const instanceCols = `id, name, email, url, status, secret_hash, domain_verified_at, domain_checked_at, quota_per_minute,
	quota_per_day, terms_version, terms_accepted_at, created_at, created_ip`

func scanInstance(row interface{ Scan(...any) error }) (Instance, error) {
	var i Instance
	err := row.Scan(&i.ID, &i.Name, &i.Email, &i.URL, &i.Status, &i.SecretHash, &i.DomainVerifiedAt, &i.DomainCheckedAt,
		&i.QuotaPerMinute, &i.QuotaPerDay, &i.TermsVersion, &i.TermsAcceptedAt, &i.CreatedAt, &i.CreatedIP)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, ErrNotFound
	}
	return i, err
}

// EmailBanned reports whether the email's hash is on the ban list.
func (s *Store) EmailBanned(ctx context.Context, emailHash []byte) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM banned_emails WHERE email_hash = ?`, emailHash).Scan(&n)
	return n > 0, err
}

// CountInstancesByEmail counts every server the email holds, banned and suspended ones included.
func (s *Store) CountInstancesByEmail(ctx context.Context, email string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM instances WHERE email = ?`, email).Scan(&n)
	return n, err
}

// CreateInstance inserts the server unless its email already holds max servers (ErrLimit), in one transaction so
// two links clicked at once cannot both pass the check.
func (s *Store) CreateInstance(ctx context.Context, i Instance, max int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM instances WHERE email = ?`, i.Email).Scan(&n); err != nil {
		return err
	}
	if n >= max {
		return ErrLimit
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO instances (`+instanceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		i.ID, i.Name, i.Email, i.URL, StatusActive, i.SecretHash, 0, 0, 0, 0, i.TermsVersion, i.TermsAcceptedAt, i.CreatedAt, i.CreatedIP); err != nil {
		return err
	}
	return tx.Commit()
}

// Instance returns the server with the ID, or ErrNotFound.
func (s *Store) Instance(ctx context.Context, id string) (Instance, error) {
	return scanInstance(s.db.QueryRowContext(ctx, `SELECT `+instanceCols+` FROM instances WHERE id = ?`, id))
}

// Instances lists every server, newest first.
func (s *Store) Instances(ctx context.Context) ([]Instance, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+instanceCols+` FROM instances ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		i, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// InstancesByEmail lists the servers an email holds, oldest first.
func (s *Store) InstancesByEmail(ctx context.Context, email string) ([]Instance, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+instanceCols+` FROM instances WHERE email = ? ORDER BY created_at`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		i, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// DueForDomainCheck lists active servers with a URL whose domain was last checked before the time.
func (s *Store) DueForDomainCheck(ctx context.Context, checkedBefore time.Time) ([]Instance, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+instanceCols+` FROM instances
		WHERE status = 'active' AND url <> '' AND domain_checked_at < ? ORDER BY domain_checked_at`, Ms(checkedBefore))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		i, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Store) exec1(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus changes a server's status. Banning also adds its email hash to the ban list.
func (s *Store) SetStatus(ctx context.Context, id, status string, emailHash []byte, now time.Time) error {
	if err := s.exec1(ctx, `UPDATE instances SET status = ? WHERE id = ?`, status, id); err != nil {
		return err
	}
	if status == StatusBanned && emailHash != nil {
		_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO banned_emails (email_hash, banned_at) VALUES (?, ?)`, emailHash, Ms(now))
		return err
	}
	return nil
}

// SuspendIfActive suspends a server only while it is active, so it never overwrites a ban. It reports whether it did.
func (s *Store) SuspendIfActive(ctx context.Context, id string) (bool, error) {
	err := s.exec1(ctx, `UPDATE instances SET status = 'suspended' WHERE id = ? AND status = 'active'`, id)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// SetSecret replaces a server's Push secret hash. The old secret stops working at once.
func (s *Store) SetSecret(ctx context.Context, id string, secretHash []byte) error {
	return s.exec1(ctx, `UPDATE instances SET secret_hash = ? WHERE id = ?`, secretHash, id)
}

// SetQuota overrides a server's limits; 0 restores the tier default.
func (s *Store) SetQuota(ctx context.Context, id string, perMinute, perDay int) error {
	return s.exec1(ctx, `UPDATE instances SET quota_per_minute = ?, quota_per_day = ? WHERE id = ?`, perMinute, perDay, id)
}

// SetDomainCheck records a domain check. A pass keeps the first verification time; a failure clears it.
func (s *Store) SetDomainCheck(ctx context.Context, id string, passed bool, now time.Time) error {
	if passed {
		return s.exec1(ctx, `UPDATE instances SET domain_checked_at = ?,
			domain_verified_at = CASE WHEN domain_verified_at = 0 THEN ? ELSE domain_verified_at END WHERE id = ?`, Ms(now), Ms(now), id)
	}
	return s.exec1(ctx, `UPDATE instances SET domain_checked_at = ?, domain_verified_at = 0 WHERE id = ?`, Ms(now), id)
}

// DeleteInstance removes a server and everything kept for it, in one transaction. Its email is not banned and
// gets the registration slot back. ErrNotFound when there is no such server.
func (s *Store) DeleteInstance(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Handles would cascade, but deleting them here does not depend on the foreign_keys pragma.
	for _, q := range []string{
		`DELETE FROM send_log WHERE instance_id = ?`,
		`DELETE FROM usage_daily WHERE instance_id = ?`,
		`DELETE FROM handles WHERE instance_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM instances WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// ── Handles ─────────────────────────────────────────────────────────────────────────────────────

// Handle is one device's registration with one server.
type Handle struct {
	Handle, InstanceID, Platform, Token string
	APNsEnv                             string // sandbox or production on iOS, empty on Android
	SecretHash                          []byte
	CreatedAt, RefreshedAt              int64
	LastSentAt, RevokedAt               int64 // 0: never / not revoked
}

// Handle returns the handle, or ErrNotFound.
func (s *Store) Handle(ctx context.Context, handle string) (Handle, error) {
	var h Handle
	err := s.db.QueryRowContext(ctx, `SELECT handle, instance_id, platform, token, coalesce(apns_env, ''), secret_hash, created_at,
		refreshed_at, last_sent_at, revoked_at FROM handles WHERE handle = ?`, handle).
		Scan(&h.Handle, &h.InstanceID, &h.Platform, &h.Token, &h.APNsEnv, &h.SecretHash, &h.CreatedAt, &h.RefreshedAt, &h.LastSentAt, &h.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Handle{}, ErrNotFound
	}
	return h, err
}

// nullable stores an empty string as NULL.
func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// UpsertHandle registers a device token with a server. The same token on the same server keeps its handle and gets
// the new secret; a revoked registration is replaced by a fresh handle. It returns the handle in use. apnsEnv is
// sandbox or production for iOS and empty for Android.
func (s *Store) UpsertHandle(ctx context.Context, newHandle, instanceID, platform, token, apnsEnv string, secretHash []byte, now time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var existing string
	var revoked int64
	err = tx.QueryRowContext(ctx, `SELECT handle, revoked_at FROM handles WHERE instance_id = ? AND token = ?`, instanceID, token).Scan(&existing, &revoked)
	switch {
	case err == nil && revoked == 0:
		if _, err := tx.ExecContext(ctx, `UPDATE handles SET secret_hash = ?, platform = ?, apns_env = ?, refreshed_at = ? WHERE handle = ?`,
			secretHash, platform, nullable(apnsEnv), Ms(now), existing); err != nil {
			return "", err
		}
		return existing, tx.Commit()
	case err == nil:
		if _, err := tx.ExecContext(ctx, `DELETE FROM handles WHERE handle = ?`, existing); err != nil {
			return "", err
		}
	case !errors.Is(err, sql.ErrNoRows):
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO handles (handle, secret_hash, instance_id, platform, token, apns_env, created_at, refreshed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, newHandle, secretHash, instanceID, platform, token, nullable(apnsEnv), Ms(now), Ms(now)); err != nil {
		return "", err
	}
	return newHandle, tx.Commit()
}

// RefreshHandleToken moves a handle to a new device token and, on iOS, APNs environment. Another registration of
// that token with the same server is dropped, since the device now answers to this handle.
func (s *Store) RefreshHandleToken(ctx context.Context, handle, instanceID, token, apnsEnv string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM handles WHERE instance_id = ? AND token = ? AND handle <> ?`, instanceID, token, handle); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE handles SET token = ?, apns_env = ?, refreshed_at = ? WHERE handle = ? AND revoked_at = 0`,
		token, nullable(apnsEnv), Ms(now), handle)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// RevokeHandle stops a handle from receiving anything.
func (s *Store) RevokeHandle(ctx context.Context, handle string, now time.Time) error {
	return s.exec1(ctx, `UPDATE handles SET revoked_at = ? WHERE handle = ? AND revoked_at = 0`, Ms(now), handle)
}

// RevokeHandleToken revokes a handle only while it is still the registration a send went to: same token, APNs
// environment and refresh time. A late failure cannot revoke what the app has since refreshed or registered again.
// ErrNotFound when the row changed or the handle is gone.
func (s *Store) RevokeHandleToken(ctx context.Context, sent Handle, now time.Time) error {
	return s.exec1(ctx, `UPDATE handles SET revoked_at = ? WHERE handle = ? AND token = ? AND coalesce(apns_env, '') = ?
		AND refreshed_at = ? AND revoked_at = 0`, Ms(now), sent.Handle, sent.Token, sent.APNsEnv, sent.RefreshedAt)
}

// CountHandles counts a server's live handles.
func (s *Store) CountHandles(ctx context.Context, instanceID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM handles WHERE instance_id = ? AND revoked_at = 0`, instanceID).Scan(&n)
	return n, err
}

// ── Sends and usage ─────────────────────────────────────────────────────────────────────────────

// Send-log statuses. A pending row holds its quota until the push provider answers.
const (
	SendPending = "pending"
	SendOK      = "ok"
	SendFailed  = "failed"
)

// PendingTimeout is how long a pending send holds its idempotency key; after that it counts as failed.
const PendingTimeout = 2 * time.Minute

// Usage field names for BumpUsage.
const (
	UsageSent          = "sent"
	UsageRateLimited   = "rate_limited"
	UsageInvalidHandle = "invalid_handle"
)

// Reservation asks to count one send before it goes to its push provider. The ciphertext itself is never stored, only its hash.
type Reservation struct {
	MessageID, InstanceID, Handle string
	ClientID                      string // the sender's idempotency key; empty for none
	At                            time.Time
	Size                          int
	CiphertextSHA256              []byte
	InstancePerDay, GlobalPerDay  int
	HandlePerDay                  int
	// DayLimit, when set, gives the server's daily quota from its row as read in the transaction, so a quota
	// change made mid-batch applies at once. It replaces InstancePerDay.
	DayLimit func(Instance) int
}

// Reserve outcomes.
type Outcome int

const (
	Reserved        Outcome = iota
	AlreadySent             // the client ID went out before; the message ID is the earlier one
	InFlight                // the client ID is being sent right now
	OverInstanceDay         // the server's daily quota is used up
	OverGlobalDay           // the relay's daily quota is used up
	OverHandleDay           // the device's daily quota is used up
	NotActive               // the server is no longer active
)

// Reserve checks the server's status, the client ID and every daily quota, and counts the send as pending, all in
// one transaction so concurrent batches cannot pass the same count. It returns the message ID in use.
func (s *Store) Reserve(ctx context.Context, r Reservation) (Outcome, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, "", err
	}
	defer tx.Rollback()
	inst, err := scanInstance(tx.QueryRowContext(ctx, `SELECT `+instanceCols+` FROM instances WHERE id = ?`, r.InstanceID))
	if errors.Is(err, ErrNotFound) {
		return NotActive, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	if inst.Status != StatusActive {
		return NotActive, "", nil
	}
	if err := releaseStale(ctx, tx, r.At); err != nil {
		return 0, "", err
	}
	dayCap := r.InstancePerDay
	if r.DayLimit != nil {
		dayCap = r.DayLimit(inst)
	}
	var clientID any
	if r.ClientID != "" {
		clientID = r.ClientID
		var msgID, st string
		var at int64
		err := tx.QueryRowContext(ctx, `SELECT message_id, status, at FROM send_log WHERE instance_id = ? AND client_id = ?`,
			r.InstanceID, r.ClientID).Scan(&msgID, &st, &at)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return 0, "", err
		case st == SendOK:
			return AlreadySent, msgID, nil
		case st == SendPending && Ms(r.At)-at < PendingTimeout.Milliseconds():
			return InFlight, "", nil
		default:
			// A failed or abandoned earlier try: release it and send again.
			if st == SendPending {
				if err := release(ctx, tx, msgID); err != nil {
					return 0, "", err
				}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE send_log SET client_id = NULL WHERE message_id = ?`, msgID); err != nil {
				return 0, "", err
			}
		}
	}
	day := Day(r.At)
	var mine, all, toHandle int
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(sum(sent), 0) FROM usage_daily WHERE instance_id = ? AND day = ?`, r.InstanceID, day).Scan(&mine); err != nil {
		return 0, "", err
	}
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(sum(sent), 0) FROM usage_daily WHERE day = ?`, day).Scan(&all); err != nil {
		return 0, "", err
	}
	y, m, d := r.At.UTC().Date()
	since := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM send_log WHERE handle = ? AND at >= ? AND status IN ('pending', 'ok')`,
		r.Handle, Ms(since)).Scan(&toHandle); err != nil {
		return 0, "", err
	}
	switch {
	case all >= r.GlobalPerDay:
		return OverGlobalDay, "", nil
	case mine >= dayCap:
		return OverInstanceDay, "", nil
	case toHandle >= r.HandlePerDay:
		return OverHandleDay, "", nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO send_log (message_id, instance_id, handle, at, size, ciphertext_sha256, status, client_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, r.MessageID, r.InstanceID, r.Handle, Ms(r.At), r.Size, r.CiphertextSHA256, SendPending, clientID); err != nil {
		return 0, "", err
	}
	if err := bump(ctx, tx, r.InstanceID, day, UsageSent); err != nil {
		return 0, "", err
	}
	return Reserved, r.MessageID, tx.Commit()
}

// FinishSend records the provider's answer for a reserved send. A send that did not go out gives its quota back.
func (s *Store) FinishSend(ctx context.Context, messageID string, ok bool, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if ok {
		var handle string
		err := tx.QueryRowContext(ctx, `UPDATE send_log SET status = 'ok' WHERE message_id = ? AND status = 'pending' RETURNING handle`,
			messageID).Scan(&handle)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE handles SET last_sent_at = ? WHERE handle = ?`, Ms(at), handle); err != nil {
			return err
		}
	} else if err := release(ctx, tx, messageID); err != nil {
		return err
	}
	return tx.Commit()
}

// release marks a pending send failed and takes it off its day's count.
func release(ctx context.Context, tx *sql.Tx, messageID string) error {
	var instanceID string
	var at int64
	err := tx.QueryRowContext(ctx, `UPDATE send_log SET status = 'failed' WHERE message_id = ? AND status = 'pending'
		RETURNING instance_id, at`, messageID).Scan(&instanceID, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE usage_daily SET sent = max(sent - 1, 0) WHERE instance_id = ? AND day = ?`,
		instanceID, Day(time.UnixMilli(at)))
	return err
}

// releaseStale gives back the quota of pending sends older than PendingTimeout, whose outcome is unknown (the relay
// stopped or a send panicked). Their ids, if any, can be sent again.
func releaseStale(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT message_id FROM send_log WHERE status = 'pending' AND at < ?`,
		Ms(now.Add(-PendingTimeout)))
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := release(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}

// SentByClientID is the status and message ID of the send a client ID last named, or ErrNotFound. A cheap look
// before rate limits are spent; Reserve decides for real.
func (s *Store) SentByClientID(ctx context.Context, instanceID, clientID string) (status, messageID string, at time.Time, err error) {
	var ms int64
	err = s.db.QueryRowContext(ctx, `SELECT status, message_id, at FROM send_log WHERE instance_id = ? AND client_id = ?`,
		instanceID, clientID).Scan(&status, &messageID, &ms)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", time.Time{}, ErrNotFound
	}
	return status, messageID, time.UnixMilli(ms), err
}

// BumpUsage adds one to a server's counter for the day.
func (s *Store) BumpUsage(ctx context.Context, instanceID string, at time.Time, field string) error {
	return bump(ctx, s.db, instanceID, Day(at), field)
}

func bump(ctx context.Context, db interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, instanceID, day, field string) error {
	switch field {
	case UsageSent, UsageRateLimited, UsageInvalidHandle:
	default:
		return fmt.Errorf("store: unknown usage field %q", field)
	}
	_, err := db.ExecContext(ctx, `INSERT INTO usage_daily (instance_id, day, `+field+`) VALUES (?, ?, 1)
		ON CONFLICT (instance_id, day) DO UPDATE SET `+field+` = `+field+` + 1`, instanceID, day)
	return err
}

// Usage is one server's counters for one day.
type Usage struct {
	Day                               string
	Sent, RateLimited, InvalidHandles int
}

// UsageFor returns a server's counters for the most recent days, newest first.
func (s *Store) UsageFor(ctx context.Context, instanceID string, days int) ([]Usage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT day, sent, rate_limited, invalid_handle FROM usage_daily
		WHERE instance_id = ? ORDER BY day DESC LIMIT ?`, instanceID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Usage
	for rows.Next() {
		var u Usage
		if err := rows.Scan(&u.Day, &u.Sent, &u.RateLimited, &u.InvalidHandles); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SentToday is what a server has sent on the day.
func (s *Store) SentToday(ctx context.Context, instanceID string, at time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT coalesce(sum(sent), 0) FROM usage_daily WHERE instance_id = ? AND day = ?`, instanceID, Day(at)).Scan(&n)
	return n, err
}

// GlobalSentToday is what every server together has sent on the day.
func (s *Store) GlobalSentToday(ctx context.Context, at time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT coalesce(sum(sent), 0) FROM usage_daily WHERE day = ?`, Day(at)).Scan(&n)
	return n, err
}

// HandleSentSince counts what reached, or is on its way to, a handle since the time.
func (s *Store) HandleSentSince(ctx context.Context, handle string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM send_log WHERE handle = ? AND at >= ? AND status IN ('pending', 'ok')`,
		handle, Ms(since)).Scan(&n)
	return n, err
}

// Retention periods.
const (
	SendLogKeep       = 30 * 24 * time.Hour
	RevokedHandleKeep = 30 * 24 * time.Hour
	UsageKeep         = 400 * 24 * time.Hour
	TokenKeep         = 24 * time.Hour // after expiry
)

// Cleanup deletes what has outlived its retention period and releases abandoned pending sends.
func (s *Store) Cleanup(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := releaseStale(ctx, tx, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, q := range []struct {
		sql string
		arg any
	}{
		{`DELETE FROM send_log WHERE at < ?`, Ms(now.Add(-SendLogKeep))},
		{`DELETE FROM handles WHERE revoked_at <> 0 AND revoked_at < ?`, Ms(now.Add(-RevokedHandleKeep))},
		{`DELETE FROM usage_daily WHERE day < ?`, Day(now.Add(-UsageKeep))},
		{`DELETE FROM email_tokens WHERE expires_at < ?`, Ms(now.Add(-TokenKeep))},
	} {
		if _, err := s.db.ExecContext(ctx, q.sql, q.arg); err != nil {
			return err
		}
	}
	return nil
}
