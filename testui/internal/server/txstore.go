package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	certcheck "github.com/vocdoni/cert-check"
)

// Store limits (spec "Main listener", transaction store).
const (
	TxLifetime      = 5 * time.Minute
	TxCapacity      = 10_000
	JanitorInterval = 30 * time.Second
	secretBytes     = 32
)

// Store errors. Callers never reveal which one happened to the client.
var (
	ErrStoreFull    = errors.New("txstore: full")
	ErrInvalidState = errors.New("txstore: state unknown, expired, used or for another provider")
	ErrInvalidCode  = errors.New("txstore: code unknown or expired")
	ErrCookie       = errors.New("txstore: cookie missing or does not match")
	ErrExpired      = errors.New("txstore: transaction expired")
)

// Secret is a 32-byte random value, base64url without padding (43 chars).
type Secret string

// NewSecret returns a fresh secret from crypto/rand.
func NewSecret() Secret {
	b := make([]byte, secretBytes)
	_, _ = rand.Read(b) // never fails since Go 1.24 (crashes instead)
	return Secret(base64.RawURLEncoding.EncodeToString(b))
}

// secretEncoding accepts only the canonical spelling of a secret: Strict
// rejects non-zero trailing bits, and hash's length check rejects the CR/LF
// that the decoder would otherwise skip.
var (
	secretEncoding = base64.RawURLEncoding.Strict()
	secretChars    = base64.RawURLEncoding.EncodedLen(secretBytes)
)

// hash returns SHA-256 of the decoded secret; ok is false for malformed input.
func (s Secret) hash() (h [32]byte, ok bool) {
	if len(s) != secretChars {
		return h, false
	}
	b, err := secretEncoding.DecodeString(string(s))
	if err != nil || len(b) != secretBytes {
		return h, false
	}
	return sha256.Sum256(b), true
}

// TxStatus is the externally visible transaction status.
type TxStatus string

// Statuses for GET /api/v1/transactions/current.
const (
	TxPending   TxStatus = "pending"
	TxCompleted TxStatus = "completed"
	TxNone      TxStatus = "none"
)

// Outcome is the stored validation outcome: exactly one of Result, Err.
type Outcome struct {
	Result *certcheck.Result
	Err    *certcheck.Error
}

// TxRef identifies a transaction whose state was consumed (input to Complete).
type TxRef struct{ id [32]byte }

// Snapshot is the cookie-bound view of a transaction.
type Snapshot struct {
	Status    TxStatus
	Provider  string
	CreatedAt time.Time
}

type tx struct {
	id        [32]byte // = cookie hash
	provider  string
	createdAt time.Time
	expiresAt time.Time
	stateHash [32]byte
	stateUsed bool
	codeHash  [32]byte
	hasCode   bool
	completed bool
	outcome   Outcome
}

// Store is the in-memory transaction store. Secrets are never retained:
// maps are keyed by SHA-256 of the decoded secret.
type Store struct {
	mu       sync.Mutex
	byCookie map[[32]byte]*tx
	byState  map[[32]byte]*tx
	byCode   map[[32]byte]*tx
	capacity int
	now      func() time.Time
}

// NewStore returns an empty store. now is the clock (nil = time.Now).
func NewStore(capacity int, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	if capacity <= 0 {
		capacity = TxCapacity
	}
	return &Store{byCookie: map[[32]byte]*tx{}, byState: map[[32]byte]*tx{}, byCode: map[[32]byte]*tx{},
		capacity: capacity, now: now}
}

// Create starts a transaction for provider. prev, when it names an existing
// transaction (the request's old cookie), is deleted first.
func (s *Store) Create(provider string, prev Secret) (cookie, state Secret, expiresAt time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if h, ok := prev.hash(); ok {
		if old, found := s.byCookie[h]; found {
			s.deleteLocked(old)
		}
	}
	if len(s.byCookie) >= s.capacity {
		s.sweepLocked(now)
		if len(s.byCookie) >= s.capacity {
			return "", "", time.Time{}, ErrStoreFull
		}
	}
	cookie, state = NewSecret(), NewSecret()
	ch, _ := cookie.hash()
	sh, _ := state.hash()
	t := &tx{id: ch, provider: provider, createdAt: now, expiresAt: now.Add(TxLifetime), stateHash: sh}
	s.byCookie[ch], s.byState[sh] = t, t
	return cookie, state, t.expiresAt, nil
}

// ConsumeState atomically consumes state. It must exist, be unexpired and
// unused, and belong to provider; the state is spent on every outcome.
func (s *Store) ConsumeState(state Secret, provider string) (TxRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := state.hash()
	if !ok {
		return TxRef{}, ErrInvalidState
	}
	t, found := s.byState[h]
	if !found {
		return TxRef{}, ErrInvalidState
	}
	delete(s.byState, h)
	if t.stateUsed || !s.now().Before(t.expiresAt) || t.provider != provider {
		t.stateUsed = true
		return TxRef{}, ErrInvalidState
	}
	t.stateUsed = true
	return TxRef{id: t.id}, nil
}

// Complete stores the outcome and issues the one-use code.
func (s *Store) Complete(ref TxRef, o Outcome) (Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, found := s.byCookie[ref.id]
	if !found || !s.now().Before(t.expiresAt) {
		return "", ErrExpired
	}
	if t.completed || !t.stateUsed {
		return "", ErrInvalidState
	}
	code := NewSecret()
	h, _ := code.hash()
	t.codeHash, t.hasCode, t.completed, t.outcome = h, true, true, o
	s.byCode[h] = t
	return code, nil
}

// Redeem atomically consumes code and returns the outcome when the code's
// transaction is the cookie's transaction (constant-time comparison of the
// hashes). The code is spent on every attempt; on success the transaction is
// deleted.
func (s *Store) Redeem(code, cookie Secret) (Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := code.hash()
	if !ok {
		return Outcome{}, ErrInvalidCode
	}
	t, found := s.byCode[h]
	if !found {
		return Outcome{}, ErrInvalidCode
	}
	delete(s.byCode, h)
	t.hasCode = false
	if !s.now().Before(t.expiresAt) {
		s.deleteLocked(t)
		return Outcome{}, ErrInvalidCode
	}
	ch, ok := cookie.hash()
	if !ok || subtle.ConstantTimeCompare(ch[:], t.id[:]) != 1 {
		return Outcome{}, ErrCookie
	}
	o := t.outcome
	s.deleteLocked(t)
	return o, nil
}

// Current returns the cookie's transaction status.
func (s *Store) Current(cookie Secret) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := cookie.hash()
	if !ok {
		return Snapshot{Status: TxNone}
	}
	t, found := s.byCookie[h]
	if !found || !s.now().Before(t.expiresAt) {
		return Snapshot{Status: TxNone}
	}
	st := TxPending
	if t.completed {
		st = TxCompleted
	}
	return Snapshot{Status: st, Provider: t.provider, CreatedAt: t.createdAt}
}

// Len returns the number of live transactions.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byCookie)
}

// RunJanitor removes expired transactions every interval until ctx ends.
func (s *Store) RunJanitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			s.sweepLocked(s.now())
			s.mu.Unlock()
		}
	}
}

func (s *Store) sweepLocked(now time.Time) {
	for _, t := range s.byCookie {
		if !now.Before(t.expiresAt) {
			s.deleteLocked(t)
		}
	}
}

func (s *Store) deleteLocked(t *tx) {
	delete(s.byCookie, t.id)
	if !t.stateUsed {
		delete(s.byState, t.stateHash)
	}
	if t.hasCode {
		delete(s.byCode, t.codeHash)
	}
}
