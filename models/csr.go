package models

import "time"

// CSR represents a Certificate Signing Request submitted by an end-entity.
// Its lifecycle is a state machine: pending → approved → issued | rejected
type CSR struct {
	ID                 uint       `json:"id" gorm:"primaryKey"`
	Subject            string     `json:"subject"`             // CN requested by the requester
	Pem                string     `json:"pem"`                 // PEM-encoded CSR
	KeyAlgorithm       string     `json:"key_algorithm"`       // RSA, ECDSA, Ed25519
	SignatureAlgorithm string     `json:"signature_algorithm"` // e.g. SHA256 and RSA
	DNSNames           []string   `json:"dns_names" gorm:"serializer:json"`
	IPAddresses        []string   `json:"ip_addresses" gorm:"serializer:json"`
	Status             CSRStatus  `json:"status"` // pending, approved, rejected, issued
	ApprovedAt         *time.Time `json:"approved_at,omitempty"`
	RejectedAt         *time.Time `json:"rejected_at,omitempty"`
	ApproverID         *uint      `json:"approver_id,omitempty"`
	Notes              string     `json:"notes,omitempty"`
	RequesterID        uint       `json:"requester_id"` // links to the customer user who submitted
	KeyPairID          *uint      `json:"key_pair_id,omitempty"` // links to the key pair used
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	DeletedAt          *time.Time `json:"deleted_at,omitempty"`
}

// CSRStatus is the lifecycle state of a CSR.
type CSRStatus string

const (
	CSRStatusPending  CSRStatus = "pending"
	CSRStatusApproved CSRStatus = "approved"
	CSRStatusRejected CSRStatus = "rejected"
	CSRStatusIssued   CSRStatus = "issued"
)

// TableName overrides GORM's default table name inference.
func (CSR) TableName() string {
	return "csrs"
}
