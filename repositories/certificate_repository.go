package repositories

import (
	"time"

	"github.com/your-org/x509-mvc/models"
	"gorm.io/gorm"
)

// CertificateRepository handles database operations for certificates.
type CertificateRepository struct {
	db *gorm.DB
}

// NewCertificateRepository constructs a CertificateRepository.
func NewCertificateRepository(db *gorm.DB) *CertificateRepository {
	return &CertificateRepository{db: db}
}

func (r *CertificateRepository) FindAll() ([]*models.Certificate, error) {
	var certs []*models.Certificate
	err := r.db.Find(&certs).Error
	return certs, err
}

// FindRootCA trả về Root CA certificate (is_ca=true, status=active) đầu tiên.
// Trả về nil, nil nếu chưa tồn tại.
func (r *CertificateRepository) FindRootCA() (*models.Certificate, error) {
	var cert models.Certificate
	err := r.db.
		Where("is_ca = ? AND status = ?", true, models.CertStatusActive).
		First(&cert).Error
	if err != nil {
		return nil, err // gorm.ErrRecordNotFound khi chưa có
	}
	return &cert, nil
}


func (r *CertificateRepository) FindByID(id uint) (*models.Certificate, error) {
	var cert models.Certificate
	err := r.db.First(&cert, id).Error
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (r *CertificateRepository) FindBySerial(serial string) (*models.Certificate, error) {
	var cert models.Certificate
	err := r.db.Where("serial = ?", serial).First(&cert).Error
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (r *CertificateRepository) FindByFingerprint(fingerprint string) (*models.Certificate, error) {
	var cert models.Certificate
	err := r.db.Where("fingerprint = ?", fingerprint).First(&cert).Error
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (r *CertificateRepository) FindBySubject(subject string) ([]*models.Certificate, error) {
	var certs []*models.Certificate
	err := r.db.Where("subject LIKE ?", "%"+subject+"%").Find(&certs).Error
	return certs, err
}

func (r *CertificateRepository) FindByIssuer(issuer string) ([]*models.Certificate, error) {
	var certs []*models.Certificate
	err := r.db.Where("issuer LIKE ?", "%"+issuer+"%").Find(&certs).Error
	return certs, err
}

func (r *CertificateRepository) FindByStatus(status models.CertStatus) ([]*models.Certificate, error) {
	var certs []*models.Certificate
	err := r.db.Where("status = ?", status).Find(&certs).Error
	return certs, err
}

func (r *CertificateRepository) FindByProfile(profile string) ([]*models.Certificate, error) {
	var certs []*models.Certificate
	err := r.db.Where("profile = ?", profile).Find(&certs).Error
	return certs, err
}

func (r *CertificateRepository) FindExpiring(withinDays int) ([]*models.Certificate, error) {
	var certs []*models.Certificate
	targetDate := time.Now().AddDate(0, 0, withinDays)
	err := r.db.Where("not_after <= ? AND status = ?", targetDate, models.CertStatusActive).Find(&certs).Error
	return certs, err
}

func (r *CertificateRepository) FindRevoked() ([]*models.Certificate, error) {
	var certs []*models.Certificate
	err := r.db.Where("is_revoked = ?", true).Find(&certs).Error
	return certs, err
}

func (r *CertificateRepository) Create(cert *models.Certificate) (*models.Certificate, error) {
	err := r.db.Create(cert).Error
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (r *CertificateRepository) Update(cert *models.Certificate) (*models.Certificate, error) {
	err := r.db.Save(cert).Error
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (r *CertificateRepository) Delete(id uint) error {
	return r.db.Delete(&models.Certificate{}, id).Error
}

// FindByRequesterID returns all certificates issued to a specific customer.
func (r *CertificateRepository) FindByRequesterID(requesterID uint) ([]*models.Certificate, error) {
	var certs []*models.Certificate
	err := r.db.Where("requester_id = ?", requesterID).Find(&certs).Error
	return certs, err
}
