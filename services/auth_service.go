package services

import (
	"time"

	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/repositories"
)

// ─── Customer Auth Service ─────────────────────────────────────────────────────

// CustomerAuthService handles customer-facing authentication.
type CustomerAuthService struct {
	authRepo *repositories.AuthRepository
	tokenSvc *TokenService
	hasher   *Hasher
}

// NewCustomerAuthService constructs a CustomerAuthService.
func NewCustomerAuthService(
	authRepo *repositories.AuthRepository,
	tokenSvc *TokenService,
	hasher *Hasher,
) *CustomerAuthService {
	return &CustomerAuthService{
		authRepo: authRepo,
		tokenSvc: tokenSvc,
		hasher:   hasher,
	}
}

// Register creates a new customer account.
func (s *CustomerAuthService) Register(username, password, name, email string) (*models.User, error) {
	if len(password) < 8 {
		return nil, models.ErrPasswordWeak
	}

	_, err := s.authRepo.FindUserByUsername(username)
	if err == nil {
		return nil, models.ErrUserAlreadyExists
	}

	hashedPwd, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Username: username,
		Password: hashedPwd,
		Name:     name,
		Email:    email,
		Role:     models.RoleCustomer,
	}

	if err := s.authRepo.CreateUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

// Login authenticates a customer and returns a token pair.
func (s *CustomerAuthService) Login(username, password string) (accessToken string, refreshToken string, expiresAt time.Time, err error) {
	user, err := s.authRepo.FindUserByUsername(username)
	if err != nil {
		return "", "", time.Time{}, models.ErrInvalidCredentials
	}

	if user.Role != models.RoleCustomer {
		return "", "", time.Time{}, models.ErrInvalidCredentials
	}

	if !s.hasher.Verify(password, user.Password) {
		return "", "", time.Time{}, models.ErrInvalidCredentials
	}

	return s.issueTokenPair(user)
}

// Refresh validates the refresh token and issues a new access token without rotation.
func (s *CustomerAuthService) Refresh(refreshToken string) (string, string, time.Time, error) {
	return refreshAccessTokenWithoutRotation(s.authRepo, s.tokenSvc, refreshToken)
}

// Logout invalidates all refresh tokens for the given customer.
func (s *CustomerAuthService) Logout(userID uint) error {
	return s.authRepo.RevokeAllUserRefreshTokens(userID)
}

// GetUserByID returns a user by ID.
func (s *CustomerAuthService) GetUserByID(userID uint) (*models.User, error) {
	return s.authRepo.FindUserByID(userID)
}

// GetUserByUsername returns a user by username.
func (s *CustomerAuthService) GetUserByUsername(username string) (*models.User, error) {
	return s.authRepo.FindUserByUsername(username)
}

// ─── Admin Auth Service ───────────────────────────────────────────────────────

// AdminAuthService handles admin-facing authentication.
type AdminAuthService struct {
	authRepo *repositories.AuthRepository
	tokenSvc *TokenService
	hasher   *Hasher
}

// NewAdminAuthService constructs an AdminAuthService.
func NewAdminAuthService(
	authRepo *repositories.AuthRepository,
	tokenSvc *TokenService,
	hasher *Hasher,
) *AdminAuthService {
	return &AdminAuthService{
		authRepo: authRepo,
		tokenSvc: tokenSvc,
		hasher:   hasher,
	}
}

// Login authenticates an admin and returns a token pair.
func (s *AdminAuthService) Login(username, password string) (string, string, time.Time, error) {
	user, err := s.authRepo.FindUserByUsername(username)
	if err != nil {
		return "", "", time.Time{}, models.ErrInvalidCredentials
	}

	if user.Role != models.RoleAdmin {
		return "", "", time.Time{}, models.ErrInvalidCredentials
	}

	if !s.hasher.Verify(password, user.Password) {
		return "", "", time.Time{}, models.ErrInvalidCredentials
	}

	return s.issueTokenPair(user)
}

// Refresh validates the refresh token and issues a new access token without rotation.
func (s *AdminAuthService) Refresh(refreshToken string) (string, string, time.Time, error) {
	return refreshAccessTokenWithoutRotation(s.authRepo, s.tokenSvc, refreshToken)
}

// Logout invalidates all refresh tokens for the given admin.
func (s *AdminAuthService) Logout(userID uint) error {
	return s.authRepo.RevokeAllUserRefreshTokens(userID)
}

// GetUserByUsername retrieves a user by username (used for admin login response).
func (s *AdminAuthService) GetUserByUsername(username string) (*models.User, error) {
	return s.authRepo.FindUserByUsername(username)
}

// ChangePassword updates an admin's password after verifying the current one.
func (s *AdminAuthService) ChangePassword(userID uint, currentPassword, newPassword string) error {
	if len(newPassword) < 8 {
		return models.ErrPasswordWeak
	}

	user, err := s.authRepo.FindUserByID(userID)
	if err != nil {
		return models.ErrAdminNotFound
	}

	if !s.hasher.Verify(currentPassword, user.Password) {
		return models.ErrPasswordIncorrect
	}

	hashed, err := s.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	return s.authRepo.UpdatePassword(userID, hashed)
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

func (s *CustomerAuthService) issueTokenPair(user *models.User) (string, string, time.Time, error) {
	return issueTokenPair(s.authRepo, s.tokenSvc, user)
}

func (s *AdminAuthService) issueTokenPair(user *models.User) (string, string, time.Time, error) {
	return issueTokenPair(s.authRepo, s.tokenSvc, user)
}

func issueTokenPair(authRepo *repositories.AuthRepository, ts *TokenService, user *models.User) (string, string, time.Time, error) {
	accessToken, _, err := ts.GenerateAccessToken(user.ID, user.Username, string(user.Role))
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshToken, tokenID, expiresAt, err := ts.GenerateRefreshToken(user.ID)
	if err != nil {
		return "", "", time.Time{}, err
	}

	rt := &models.RefreshToken{
		TokenID:   tokenID,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
	}
	_ = authRepo.CreateRefreshToken(rt)

	return accessToken, refreshToken, expiresAt, nil
}

func refreshAccessTokenWithoutRotation(authRepo *repositories.AuthRepository, ts *TokenService, refreshToken string) (string, string, time.Time, error) {
	claims, err := ts.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", "", time.Time{}, err
	}

	storedRT, err := authRepo.FindRefreshToken(claims.TokenID)
	if err != nil || !storedRT.IsValid() {
		return "", "", time.Time{}, models.ErrRefreshTokenInvalid
	}

	user, err := authRepo.FindUserByID(claims.UserID)
	if err != nil {
		return "", "", time.Time{}, models.ErrUserNotFound
	}

	accessToken, _, err := ts.GenerateAccessToken(user.ID, user.Username, string(user.Role))
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Trả lại AccessToken mới, và giữ nguyên RefreshToken cũ + thời gian hết hạn cũ
	return accessToken, refreshToken, storedRT.ExpiresAt, nil
}
