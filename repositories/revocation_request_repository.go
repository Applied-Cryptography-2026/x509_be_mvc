package repositories

import (
	"github.com/your-org/x509-mvc/models"
	"gorm.io/gorm"
)

// RevocationRequestRepository handles DB operations for revocation requests.
type RevocationRequestRepository struct {
	db *gorm.DB
}

// NewRevocationRequestRepository constructs a RevocationRequestRepository.
func NewRevocationRequestRepository(db *gorm.DB) *RevocationRequestRepository {
	return &RevocationRequestRepository{db: db}
}

// FindAll returns all revocation requests, newest first.
func (r *RevocationRequestRepository) FindAll() ([]*models.RevocationRequest, error) {
	var reqs []*models.RevocationRequest
	err := r.db.Order("created_at DESC").Find(&reqs).Error
	return reqs, err
}

// FindByID returns a single revocation request by ID.
func (r *RevocationRequestRepository) FindByID(id uint) (*models.RevocationRequest, error) {
	var req models.RevocationRequest
	err := r.db.First(&req, id).Error
	if err != nil {
		return nil, err
	}
	return &req, nil
}

// FindByRequesterID returns all revocation requests for a specific customer.
func (r *RevocationRequestRepository) FindByRequesterID(requesterID uint) ([]*models.RevocationRequest, error) {
	var reqs []*models.RevocationRequest
	err := r.db.Where("requester_id = ?", requesterID).Order("created_at DESC").Find(&reqs).Error
	return reqs, err
}

// FindPending returns all pending revocation requests, newest first.
func (r *RevocationRequestRepository) FindPending() ([]*models.RevocationRequest, error) {
	var reqs []*models.RevocationRequest
	err := r.db.Where("status = ?", models.RevokeStatusPending).Order("created_at DESC").Find(&reqs).Error
	return reqs, err
}

// FindByCertificateID returns all revocation requests for a specific certificate.
func (r *RevocationRequestRepository) FindByCertificateID(certID uint) ([]*models.RevocationRequest, error) {
	var reqs []*models.RevocationRequest
	err := r.db.Where("certificate_id = ?", certID).Find(&reqs).Error
	return reqs, err
}

// Create inserts a new revocation request.
func (r *RevocationRequestRepository) Create(req *models.RevocationRequest) (*models.RevocationRequest, error) {
	err := r.db.Create(req).Error
	return req, err
}

// Update updates an existing revocation request.
func (r *RevocationRequestRepository) Update(req *models.RevocationRequest) (*models.RevocationRequest, error) {
	err := r.db.Save(req).Error
	return req, err
}

// Delete soft-deletes a revocation request.
func (r *RevocationRequestRepository) Delete(id uint) error {
	return r.db.Delete(&models.RevocationRequest{}, id).Error
}