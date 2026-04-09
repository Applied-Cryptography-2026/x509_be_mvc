package models

import "time"

// Certificate represents the core domain entity for an x509 certificate.
// In MVC, models are the data layer — pure structs with GORM tags for
// persistence and JSON tags for API responses.
type Certificate struct {
	ID          uint       `json:"id" gorm:"primaryKey"`
	Subject     string     `json:"subject"`       // CN, O, OU, etc. (PKIX directory string)
	Issuer      string     `json:"issuer"`        // CN, O, OU of issuing CA
	Serial      string     `json:"serial"`        // Certificate serial number (hex)
	Fingerprint string     `json:"fingerprint"`   // SHA-256 fingerprint (hex, colon-separated)
	NotBefore   time.Time  `json:"not_before"`    // Validity start
	NotAfter    time.Time  `json:"not_after"`     // Validity end
	KeyUsage    []string   `json:"key_usage" gorm:"serializer:json"`     // digitalSignature, keyEncipherment, etc.
	ExtKeyUsage []string   `json:"ext_key_usage" gorm:"serializer:json"` // serverAuth, clientAuth, etc.
	DNSNames    []string   `json:"dns_names" gorm:"serializer:json"`     // SAN DNS names
	IPAddresses []string   `json:"ip_addresses" gorm:"serializer:json"`  // SAN IP addresses
	IsCA        bool       `json:"is_ca"`         // Whether this cert is a CA certificate
	IsRevoked   bool       `json:"is_revoked"`    // Whether the cert has been revoked
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CRLURL      string     `json:"crl_url"`             // CRL distribution point
	OCSPURL     string     `json:"ocsp_url"`            // OCSP responder URL
	CertPEM     string     `json:"cert_pem"`            // PEM-encoded certificate
	KeyPEM      string     `json:"key_pem,omitempty"`   // PEM-encoded private key (stored encrypted at rest)
	ParentID    *uint      `json:"parent_id,omitempty"` // FK to issuer CA certificate
	Profile     string     `json:"profile"`             // e.g. "tls-server", "tls-client", "code-signing"
	Status      CertStatus `json:"status"`              // active, expired, revoked, pending
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

// CertStatus represents the operational lifecycle status of a certificate.
type CertStatus string

const (
	CertStatusActive  CertStatus = "active"
	CertStatusExpired CertStatus = "expired"
	CertStatusRevoked CertStatus = "revoked"
	CertStatusPending CertStatus = "pending"
	CertStatusHold    CertStatus = "hold"
)

// TableName overrides GORM's default table name inference.
func (Certificate) TableName() string {
	return "certificates"
}

// IsExpired returns true when the certificate's NotAfter has passed.
func (c *Certificate) IsExpired() bool {
	return time.Now().After(c.NotAfter)
}

// IsValid returns true when the cert is active and not expired or revoked.
func (c *Certificate) IsValid() bool {
	return c.Status == CertStatusActive && !c.IsExpired() && !c.IsRevoked
}
