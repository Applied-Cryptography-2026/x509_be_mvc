package models

import "time"

// AuditLog represents an audit log entry in the database
type AuditLog struct {
	ID          int64     `gorm:"primaryKey;column:id" json:"id"`
	UserID      *int      `gorm:"column:user_id" json:"user_id"`
	UserEmail   *string   `gorm:"column:user_email" json:"user_email"`
	Action      string    `gorm:"column:action" json:"action"`
	EntityType  *string   `gorm:"column:entity_type" json:"entity_type"`
	EntityID    *int      `gorm:"column:entity_id" json:"entity_id"`
	Description *string   `gorm:"column:description" json:"description"`
	CreatedAt   time.Time `gorm:"column:created_at" json:"created_at"`
}

// TableName specifies the table name for AuditLog
func (AuditLog) TableName() string {
	return "audit_logs"
}

// AuditLogResponse is the format returned to frontend
type AuditLogResponse struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Action    string `json:"action"`
	Entity    string `json:"entity"`
	Details   string `json:"details"`
}

// ToResponse converts AuditLog to response format
func (a *AuditLog) ToResponse() *AuditLogResponse {
	return &AuditLogResponse{
		ID:        a.ID,
		Timestamp: a.CreatedAt.Format("2006-01-02 15:04:05"),
		User:      strOrEmpty(a.UserEmail),
		Action:    generateActionDisplay(a.Action, a.EntityType),
		Entity:    strOrEmpty(a.EntityType),
		Details:   strOrEmpty(a.Description),
	}
}

// Helper function
func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// generateActionDisplay creates display format like "CERTIFICATE_ISSUED"
func generateActionDisplay(action string, entityType *string) string {
	entity := strOrEmpty(entityType)
	if entity == "" {
		entity = "SYSTEM"
	}
	
	actionMap := map[string]string{
		"create":             "CREATED",
		"update":             "UPDATED",
		"delete":             "DELETED",
		"approve":            "APPROVED",
		"reject":             "REJECTED",
		"revoke":             "REVOKED",
		"revoke_directly":    "REVOKED",
		"export":             "EXPORTED",
		"import":             "IMPORTED",
		"login":              "LOGIN",
		"logout":             "LOGOUT",
		"register":           "REGISTERED",
		"download":           "DOWNLOADED",
		"upload":             "UPLOADED",
		"generate_root_ca":   "GENERATED",
		"cancel":             "CANCELLED",
		"validate":           "VALIDATED",
	}
	
	if displayAction, ok := actionMap[action]; ok {
		return entity + "_" + displayAction
	}
	
	return entity + "_" + action
}