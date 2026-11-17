// Package cursor encodes the resumable state of a paged traversal into an
// opaque, HMAC-signed token. The token carries everything needed to resume a
// read: the frozen query request, the snapshot sequence, the last delivered
// keyset position and the absolute idle deadline. Signing it means a token
// minted before a restart remains verifiable afterwards using the same
// instance secret, while forged or truncated tokens are rejected.
package cursor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// tokenVersion guards future wire formats.
	tokenVersion = 1
	// MaxToken bounds the work a client can force through token decoding.
	MaxToken  = 900 * 1024
	secretLen = 32
)

// Token is the signed, client-held resume handle. JSON fields are ordered
// and stable because the whole struct is the authenticated payload.
type Token struct {
	Version   int            `json:"version"`
	CursorID  string         `json:"cursor_id"`
	Query     QueryEnvelope  `json:"query"`
	Snapshot  uint64         `json:"snapshot"`
	Position  []PositionCell `json:"position,omitempty"`
	PageSize  int            `json:"page_size"`
	TTL       int64          `json:"ttl_seconds"`
	ExpiresAt int64          `json:"expires_at_unix"`
}

// QueryEnvelope is the query request as frozen when the cursor opened.
type QueryEnvelope struct {
	Relation    string              `json:"relation"`
	Columns     []string            `json:"columns,omitempty"`
	Where       []PredicateEnvelope `json:"where,omitempty"`
	Order       []OrderingEnvelope  `json:"order,omitempty"`
	At          *uint64             `json:"at,omitempty"`
	Transaction string              `json:"transaction,omitempty"`
	ForceScan   bool                `json:"force_scan,omitempty"`
}

// PredicateEnvelope mirrors query.Predicate with a JSON-safe scalar cell.
type PredicateEnvelope struct {
	Column string       `json:"column"`
	Op     string       `json:"op"`
	Value  PositionCell `json:"value"`
}

// OrderingEnvelope mirrors query.Ordering.
type OrderingEnvelope struct {
	Column string `json:"column"`
	Desc   bool   `json:"desc"`
}

// PositionCell is a datum value in portable form. Kind is one of
// int/text/bool/null; Int, Text and Bool carry the payload.
type PositionCell struct {
	Kind string `json:"kind"`
	Int  int64  `json:"int,omitempty"`
	Text string `json:"text,omitempty"`
	Bool bool   `json:"bool,omitempty"`
}

var (
	// ErrMalformed means the token is not a recognizable lamina token.
	ErrMalformed = errors.New("malformed cursor token")
	// ErrForged means the token structure parsed but its signature failed.
	ErrForged = errors.New("cursor token signature invalid")
)

// Encode serializes and signs a token: lamina1.<base64url payload>.<hmac>.
func Encode(secret []byte, t Token) (string, error) {
	t.Version = tokenVersion
	payload, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	signature := mac.Sum(nil)
	return "lamina1." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Decode verifies the structure and signature, then returns the token.
func Decode(secret []byte, encoded string) (Token, error) {
	var t Token
	if len(encoded) == 0 || len(encoded) > MaxToken {
		return t, ErrMalformed
	}
	prefix := "lamina1."
	if len(encoded) <= len(prefix) || encoded[:len(prefix)] != prefix {
		return t, ErrMalformed
	}
	rest := encoded[len(prefix):]
	dot := -1
	for i := len(rest) - 1; i >= 0; i-- {
		if rest[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 || dot == len(rest)-1 {
		return t, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(rest[:dot])
	if err != nil {
		return t, ErrMalformed
	}
	signature, err := base64.RawURLEncoding.DecodeString(rest[dot+1:])
	if err != nil {
		return t, ErrMalformed
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), signature) {
		return t, ErrForged
	}
	if err = json.Unmarshal(payload, &t); err != nil {
		return t, ErrMalformed
	}
	if t.Version != tokenVersion || t.CursorID == "" || t.TTL <= 0 || t.ExpiresAt <= 0 || t.PageSize <= 0 {
		return t, ErrMalformed
	}
	return t, nil
}

// NewID returns a random 128-bit hex cursor identifier.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// LoadSecret returns the per-instance HMAC secret, creating a new random one
// in the data directory on first use. The file is never exported in backups,
// so tokens are only resumable against the same data directory; a missing or
// unreadable secret after restart turns every old token into a clean 404.
func LoadSecret(dir string) ([]byte, error) {
	path := filepath.Join(dir, "cursor.secret")
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != secretLen {
			return nil, fmt.Errorf("cursor secret has invalid length")
		}
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	secret := make([]byte, secretLen)
	if _, err = rand.Read(secret); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".cursor-secret-")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(secret); err != nil {
		tmp.Close()
		return nil, err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err = tmp.Close(); err != nil {
		return nil, err
	}
	if err = os.Chmod(tmpName, 0600); err != nil {
		return nil, err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return nil, err
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return nil, err
	}
	return secret, nil
}
