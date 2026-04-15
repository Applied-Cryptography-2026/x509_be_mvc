package models

import "time"

// KeyPair represents a cryptographic key pair generated and stored by a customer.
type KeyPair struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Name         string    `json:"name" gorm:"size:255;not null"`
	Algorithm    string    `json:"algorithm" gorm:"size:16;not null"` // RSA, ECDSA
	KeySize      int       `json:"key_size" gorm:"not null"`           // 2048, 4096, 256, 384
	PublicKeyPEM string    `json:"public_key_pem" gorm:"type:longtext;not null"`
	PrivateKeyPEM string   `json:"-" gorm:"type:longtext;not null"` // encrypted, never exposed via API by default
	Fingerprint  string    `json:"fingerprint" gorm:"size:128;not null"` // SHA-256 of public key bytes
	OwnerID      uint      `json:"owner_id" gorm:"not null;index"`
	CreatedAt    time.Time `json:"created_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}

// TableName overrides GORM's default table name inference.
func (KeyPair) TableName() string {
	return "key_pairs"
}
