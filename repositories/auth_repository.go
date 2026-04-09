package repositories

import (
	"github.com/your-org/x509-mvc/models"
	"gorm.io/gorm"
)

// AuthRepository handles database operations for auth-related data.
type AuthRepository struct {
	db *gorm.DB
}

// NewAuthRepository constructs an AuthRepository.
func NewAuthRepository(db *gorm.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

// ─── Refresh Token operations ─────────────────────────────────────────────────

func (r *AuthRepository) CreateRefreshToken(rt *models.RefreshToken) error {
	return r.db.Create(rt).Error
}

func (r *AuthRepository) FindRefreshToken(tokenID string) (*models.RefreshToken, error) {
	var rt models.RefreshToken
	err := r.db.Where("token_id = ?", tokenID).First(&rt).Error
	return &rt, err
}

func (r *AuthRepository) RevokeRefreshToken(tokenID string) error {
	return r.db.Model(&models.RefreshToken{}).
		Where("token_id = ?", tokenID).
		Update("revoked_at", gorm.Expr("NOW()")).Error
}

func (r *AuthRepository) RevokeAllUserRefreshTokens(userID uint) error {
	return r.db.Model(&models.RefreshToken{}).
		Where("user_id = ?", userID).
		Where("revoked_at IS NULL").
		Update("revoked_at", gorm.Expr("NOW()")).Error
}

func (r *AuthRepository) MarkRefreshTokenUsed(tokenID string) error {
	return r.db.Model(&models.RefreshToken{}).
		Where("token_id = ?", tokenID).
		Update("is_used", true).Error
}

// ─── User operations ─────────────────────────────────────────────────────────

func (r *AuthRepository) FindUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepository) FindUserByID(id uint) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepository) CreateUser(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *AuthRepository) UpdatePassword(userID uint, hashedPassword string) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Update("password", hashedPassword).Error
}
