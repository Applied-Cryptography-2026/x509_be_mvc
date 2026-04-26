package services

import (
	"log"
	"time"

	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/repositories"
)

// AuditLogService handles audit log operations
type AuditLogService struct {
	repo     *repositories.AuditLogRepository
	authRepo *repositories.AuthRepository
}

// NewAuditLogService constructs AuditLogService
func NewAuditLogService(repo *repositories.AuditLogRepository, authRepo *repositories.AuthRepository) *AuditLogService {
	return &AuditLogService{
		repo:     repo,
		authRepo: authRepo,
	}
}

// LogRequest represents parameters for creating an audit log
type LogRequest struct {
	UserID      *int
	UserEmail   *string
	Action      string
	EntityType  *string
	EntityID    *int
	Description string
}

// Record creates an audit log entry
func (s *AuditLogService) Record(req *LogRequest) error {
	// If UserEmail not provided but UserID is, fetch from database
	userEmail := req.UserEmail
	if userEmail == nil && req.UserID != nil {
		if user, err := s.authRepo.FindUserByID(uint(*req.UserID)); err == nil {
			userEmail = &user.Email
		}
	}

	auditLog := &models.AuditLog{
		UserID:      req.UserID,
		UserEmail:   userEmail,
		Action:      req.Action,
		EntityType:  req.EntityType,
		EntityID:    req.EntityID,
		Description: &req.Description,
		CreatedAt:   time.Now(),
	}
	err := s.repo.Create(auditLog)
	if err != nil {
		log.Printf("[ERROR] Audit log failed to record: %v | UserID: %v, Action: %s, EntityType: %v, Description: %s",
			err, req.UserID, req.Action, req.EntityType, req.Description)
	}
	return err
}

// GetAuditLogs retrieves all audit logs without pagination
func (s *AuditLogService) GetAuditLogs() ([]*models.AuditLog, error) {
	return s.repo.FindAll()
}

// GetByDateRange retrieves all logs within date range
func (s *AuditLogService) GetByDateRange(startDate, endDate string) ([]*models.AuditLog, error) {
	return s.repo.FindByDateRange(startDate, endDate)
}

// GetByUserEmail retrieves logs for a specific user by email
func (s *AuditLogService) GetByUserEmail(userEmail string) ([]*models.AuditLog, error) {
	return s.repo.FindByUserEmail(userEmail)
}

// GetByDateRangeAndUser retrieves logs within date range for a specific user
func (s *AuditLogService) GetByDateRangeAndUser(startDate, endDate, userEmail string) ([]*models.AuditLog, error) {
	return s.repo.FindByDateRangeAndUser(startDate, endDate, userEmail)
}

// Helper
func strPtr(s string) *string {
	return &s
}

// IntPtr converts uint to *int
func IntPtr(u uint) *int {
	i := int(u)
	return &i
}
