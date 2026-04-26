package repositories

import (
	"github.com/your-org/x509-mvc/models"
	"gorm.io/gorm"
)

// AuditLogRepository handles simple audit log database operations
type AuditLogRepository struct {
	db *gorm.DB
}

// NewAuditLogRepository constructs an AuditLogRepository
func NewAuditLogRepository(db *gorm.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

// Create inserts a new audit log
func (r *AuditLogRepository) Create(log *models.AuditLog) error {
	return r.db.Create(log).Error
}

// FindAll retrieves all audit logs
func (r *AuditLogRepository) FindAll() ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	
	err := r.db.
		Order("created_at DESC").
		Find(&logs).Error
	
	return logs, err
}

// FindByDateRange retrieves all logs within date range
func (r *AuditLogRepository) FindByDateRange(startDate, endDate string) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	
	err := r.db.
		Where("DATE(created_at) BETWEEN ? AND ?", startDate, endDate).
		Order("created_at DESC").
		Find(&logs).Error
	
	return logs, err
}


// FindByUserEmail retrieves logs for a specific user by email
func (r *AuditLogRepository) FindByUserEmail(userEmail string) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	
	err := r.db.
		Where("user_email = ?", userEmail).
		Order("created_at DESC").
		Find(&logs).Error
	
	return logs, err
}

// FindByDateRangeAndUser retrieves logs within date range for a specific user
func (r *AuditLogRepository) FindByDateRangeAndUser(startDate, endDate, userEmail string) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	
	err := r.db.
		Where("DATE(created_at) BETWEEN ? AND ? AND user_email = ?", startDate, endDate, userEmail).
		Order("created_at DESC").
		Find(&logs).Error
	
	return logs, err
}
