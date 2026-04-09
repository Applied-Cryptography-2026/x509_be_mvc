package models

import "time"

// Role represents the user role in the system.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleCustomer Role = "customer"
)

// User represents an authenticated user (admin or customer).
type User struct {
	ID        uint       `json:"id" gorm:"primaryKey"`
	Username  string     `json:"username" gorm:"uniqueIndex;size:50;not null"`
	Password  string     `json:"-" gorm:"size:255;not null"`
	Name      string     `json:"name"`
	Role      Role       `json:"role" gorm:"size:20;not null;default:customer"`
	Email     string     `json:"email" gorm:"size:255"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// IsAdmin returns true if the user is an administrator.
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// RefreshToken represents a stored refresh token for token rotation.
type RefreshToken struct {
	ID        uint       `json:"id" gorm:"primaryKey"`
	TokenID   string     `json:"token_id" gorm:"uniqueIndex;size:64;not null"`
	UserID    uint       `json:"user_id" gorm:"not null;index"`
	ExpiresAt time.Time  `json:"expires_at" gorm:"not null"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	IsUsed    bool       `json:"is_used" gorm:"default:false"`
}

// IsExpired returns true if the refresh token has expired.
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsValid returns true if the token is not expired, not revoked, and not used.
func (rt *RefreshToken) IsValid() bool {
	return !rt.IsExpired() && rt.RevokedAt == nil && !rt.IsUsed
}
