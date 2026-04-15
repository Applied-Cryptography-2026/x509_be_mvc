package repositories

import (
	"github.com/your-org/x509-mvc/models"
	"gorm.io/gorm"
)

// KeyPairRepository handles DB operations for key pairs.
type KeyPairRepository struct {
	db *gorm.DB
}

// NewKeyPairRepository constructs a KeyPairRepository.
func NewKeyPairRepository(db *gorm.DB) *KeyPairRepository {
	return &KeyPairRepository{db: db}
}

// FindByOwnerID returns all key pairs for a given owner (soft-deleted excluded).
func (r *KeyPairRepository) FindByOwnerID(ownerID uint) ([]*models.KeyPair, error) {
	var kps []*models.KeyPair
	err := r.db.Where("owner_id = ?", ownerID).Find(&kps).Error
	return kps, err
}

// FindByID returns a key pair by ID.
func (r *KeyPairRepository) FindByID(id uint) (*models.KeyPair, error) {
	var kp models.KeyPair
	err := r.db.First(&kp, id).Error
	return &kp, err
}

// Create saves a new key pair.
func (r *KeyPairRepository) Create(kp *models.KeyPair) (*models.KeyPair, error) {
	err := r.db.Create(kp).Error
	return kp, err
}

// Delete soft-deletes a key pair by ID.
func (r *KeyPairRepository) Delete(id uint) error {
	return r.db.Delete(&models.KeyPair{}, id).Error
}
