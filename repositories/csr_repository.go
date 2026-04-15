package repositories

import (
	"github.com/your-org/x509-mvc/models"
	"gorm.io/gorm"
)

// CSRRepository handles database operations for CSRs.
type CSRRepository struct {
	db *gorm.DB
}

// NewCSRRepository constructs a CSRRepository.
func NewCSRRepository(db *gorm.DB) *CSRRepository {
	return &CSRRepository{db: db}
}

// FindAll trả về toàn bộ CSR trong hệ thống.
func (r *CSRRepository) FindAll() ([]*models.CSR, error) {
	var csrs []*models.CSR
	err := r.db.Find(&csrs).Error
	return csrs, err
}

// FindByID tìm CSR theo primary key.
// Trả về gorm.ErrRecordNotFound nếu không tồn tại.
func (r *CSRRepository) FindByID(id uint) (*models.CSR, error) {
	var csr models.CSR
	err := r.db.First(&csr, id).Error
	if err != nil {
		return nil, err
	}
	return &csr, nil
}

// FindBySubject tìm tất cả CSR có subject khớp.
func (r *CSRRepository) FindBySubject(subject string) ([]*models.CSR, error) {
	var csrs []*models.CSR
	err := r.db.Where("subject = ?", subject).Find(&csrs).Error
	return csrs, err
}

// FindByStatus lọc CSR theo trạng thái (pending, approved, rejected, issued).
func (r *CSRRepository) FindByStatus(status models.CSRStatus) ([]*models.CSR, error) {
	var csrs []*models.CSR
	err := r.db.Where("status = ?", status).Find(&csrs).Error
	return csrs, err
}

// FindPending là shortcut cho FindByStatus(CSRStatusPending).
func (r *CSRRepository) FindPending() ([]*models.CSR, error) {
	return r.FindByStatus(models.CSRStatusPending)
}

// FindByRequesterID trả về tất cả CSR thuộc về 1 user cụ thể.
func (r *CSRRepository) FindByRequesterID(requesterID uint) ([]*models.CSR, error) {
	var csrs []*models.CSR
	err := r.db.Where("requester_id = ?", requesterID).Find(&csrs).Error
	return csrs, err
}

// Create lưu CSR mới vào DB. GORM tự điền ID, CreatedAt, UpdatedAt.
func (r *CSRRepository) Create(csr *models.CSR) (*models.CSR, error) {
	err := r.db.Create(csr).Error
	if err != nil {
		return nil, err
	}
	return csr, nil
}

// Update lưu toàn bộ thay đổi của CSR (Save update tất cả field, kể cả zero-value).
func (r *CSRRepository) Update(csr *models.CSR) (*models.CSR, error) {
	err := r.db.Save(csr).Error
	if err != nil {
		return nil, err
	}
	return csr, nil
}

// Delete xóa CSR theo ID (hard delete).
func (r *CSRRepository) Delete(id uint) error {
	return r.db.Delete(&models.CSR{}, id).Error
}
