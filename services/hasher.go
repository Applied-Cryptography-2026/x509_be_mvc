package services

import (
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

// Hasher provides password hashing and verification.
type Hasher struct{}

func NewHasher() *Hasher { return &Hasher{} }

// Hash hashes a plaintext password using bcrypt.
func (h *Hasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Verify checks a plaintext password against a bcrypt hash.
func (h *Hasher) Verify(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// readRandomBytes fills b with random bytes from crypto/rand.
func readRandomBytes(b []byte) (int, error) {
	return rand.Read(b)
}
