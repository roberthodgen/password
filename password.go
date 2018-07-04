// Package password is a password hashing, salting, and matching library.
// This is an opinionated library for password hashing and matching.
// It simply concatenates a plain text password with a salt then hashes it!
// Also provides random salt generation.
// Reasonable defaults are made but overrideable.
// Because a single Hash shares the HashFn: Hash is not safe to share between threads!
// Assumptions are made that you will check the plain text passwords for complexity requirements.
// No complexity checks are made in this library.
package password

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/pkg/errors"
	"hash"
)

const DefaultSaltLength = 16

// ErrIncorrect is means a match did not occur.
var ErrIncorrect = errors.New("incorrect password")

// Hash stores configuration and password hash data.
type Hash struct {
	SaltLength int // number of random bytes to read in Hash.Generate
	HashFn     hash.Hash // the hash function to be used
	Hash       string // the supplied or computed hash of (plain text bytes + salt bytes)
	Salt       string // the supplied or generated random salt
}

// New returns an empty Hash struct with reasonable defaults. Typically for use with Hash.Generate.
func New() Hash {
	return Hash{
		SaltLength: DefaultSaltLength,
		HashFn:     sha256.New(),
	}
}

// Generate a Hash and random Salt for a given plain text password using the HashFn.
// The random Salt will be read via rand.Read() (with a length of Hash.SaltLength).
func (h *Hash) Generate(plainText string) error {
	b := make([]byte, h.SaltLength)
	if _, err := rand.Read(b); err != nil {
		return err
	}

	h.HashFn.Reset() // potentially allow reuse
	h.HashFn.Write([]byte(plainText))
	h.HashFn.Write(b)
	h.Salt = hex.EncodeToString(b)
	h.Hash = hex.EncodeToString(h.HashFn.Sum(nil))
	return nil
}

// NewChecker returns a Hash struct populated with a given HashFn and salt and reasonable defaults. Use with Check.
func NewChecker(hash, salt string) Hash {
	return Hash{
		SaltLength: DefaultSaltLength,
		HashFn:     sha256.New(),
		Hash:       hash,
		Salt:       salt,
	}
}

// Check checks a plain text password against the stored Hash and Salt.
// To use: pass in a plain text password after building a Hash with NewChecker. Check returned err != nil for success.
// For granular error control, use: err == ErrIncorrect
func (h *Hash) Check(plainText string) error {
	b, err := hex.DecodeString(h.Salt)
	if err != nil {
		return err
	}

	h.HashFn.Reset() // allow reuse
	h.HashFn.Write([]byte(plainText))
	h.HashFn.Write(b)
	if result := hex.EncodeToString(h.HashFn.Sum(nil)); result != h.Hash {
		return ErrIncorrect
	}

	return nil
}
