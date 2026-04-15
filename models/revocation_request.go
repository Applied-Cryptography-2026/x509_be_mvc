package models

import "time"

// RevocationRequest represents a customer's request to revoke one of their certificates.
type RevocationRequest struct {
	ID            uint       `json:"id" gorm:"primaryKey"`
	CertificateID uint      `json:"certificate_id" gorm:"index"`
	RequesterID   uint      `json:"requester_id" gorm:"index"`
	Reason        string    `json:"reason"`
	Status        RevokeStatus `json:"status" gorm:"type:varchar(32);default:'pending'"`
	AdminID       *uint     `json:"admin_id,omitempty" gorm:"index"`
	AdminNotes    string    `json:"admin_notes,omitempty"`
	ProcessedAt   *time.Time `json:"processed_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}

// RevokeStatus mirrors CertStatus for revocation request lifecycle.
type RevokeStatus string

const (
	RevokeStatusPending  RevokeStatus = "pending"
	RevokeStatusApproved RevokeStatus = "approved"
	RevokeStatusRejected RevokeStatus = "rejected"
)

// TableName overrides GORM's default table name inference.
func (RevocationRequest) TableName() string {
	return "revocation_requests"
}
