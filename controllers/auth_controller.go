package controllers

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/services"
)

// CustomerRegisterRequest is the request body for customer registration.
type CustomerRegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Email    string `json:"email"`
}

// CustomerLoginRequest is the request body for customer login.
type CustomerLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenResponse is the standard token payload returned to clients.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// ErrorResponse is the standard JSON error shape.
type ErrorResponse struct {
	Error string `json:"error"`
}

// AuthController handles customer-facing authentication endpoints.
type AuthController struct {
	svc *services.CustomerAuthService
}

// NewAuthController constructs the customer auth controller.
func NewAuthController(svc *services.CustomerAuthService) *AuthController {
	return &AuthController{svc: svc}
}

// Register handles POST /auth/register.
// Anyone can register as a customer (role: customer).
func (ac *AuthController) Register(c echo.Context) error {
	var req CustomerRegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
	}
	if req.Username == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "username and password are required"})
	}

	user, err := ac.svc.Register(req.Username, req.Password, req.Name, req.Email)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"name":     user.Name,
		"email":    user.Email,
		"role":     user.Role,
	})
}

// Login handles POST /auth/login.
// Authenticates a customer and sets a refresh-token httpOnly cookie.
func (ac *AuthController) Login(c echo.Context) error {
	var req CustomerLoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
	}
	if req.Username == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "username and password are required"})
	}

	accessToken, refreshToken, expiresAt, err := ac.svc.Login(req.Username, req.Password)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
	}

	// Look up user info for the response payload
	fetchedUser, err := ac.svc.GetUserByUsername(req.Username)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to load user"})
	}

	ac.setRefreshCookie(c, refreshToken, expiresAt)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token": accessToken,
		"expires_in":   int64(time.Until(expiresAt).Seconds()),
		"user": map[string]interface{}{
			"id":       fetchedUser.ID,
			"username": fetchedUser.Username,
			"name":     fetchedUser.Name,
			"email":    fetchedUser.Email,
			"role":     fetchedUser.Role,
		},
	})
}

// Refresh handles POST /auth/refresh.
// Validates the refresh-token cookie, rotates it, and issues a new token pair.
func (ac *AuthController) Refresh(c echo.Context) error {
	rawToken, ok := c.Get("raw_refresh_token").(string)
	if !ok || rawToken == "" {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "refresh token missing"})
	}

	accessToken, newRefreshToken, expiresAt, err := ac.svc.Refresh(rawToken)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
	}

	ac.clearRefreshCookie(c)
	ac.setRefreshCookie(c, newRefreshToken, expiresAt)

	return c.JSON(http.StatusOK, TokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   int64(time.Until(expiresAt).Seconds()),
	})
}

// Logout handles POST /auth/logout.
func (ac *AuthController) Logout(c echo.Context) error {
	userID, ok := c.Get("user_id").(uint)
	if !ok {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
	}

	if err := ac.svc.Logout(userID); err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to logout"})
	}

	ac.clearRefreshCookie(c)
	return c.JSON(http.StatusOK, map[string]string{"message": "logged out"})
}

// GetMe returns the current authenticated user's info.
// GET /auth/me
func (ac *AuthController) GetMe(c echo.Context) error {
	userID, ok := c.Get("user_id").(uint)
	if !ok {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
	}

	user, err := ac.svc.GetUserByID(userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{Error: "user not found"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"name":     user.Name,
		"email":    user.Email,
		"role":     user.Role,
	})
}

// ─── Cookie helpers ──────────────────────────────────────────────────────────

func (ac *AuthController) setRefreshCookie(c echo.Context, token string, expiresAt time.Time) {
	c.SetCookie(&http.Cookie{Name: "refresh_token", Value: token, MaxAge: int(time.Until(expiresAt).Seconds()), Path: "/", Domain: "", Secure: true, HttpOnly: true})
}

func (ac *AuthController) clearRefreshCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{Name: "refresh_token", Value: "", MaxAge: -1, Path: "/", Domain: "", Secure: true, HttpOnly: true})
}
