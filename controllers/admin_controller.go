package controllers

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/services"
)

// AdminLoginRequest is the request body for admin login.
type AdminLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Changing admin password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// AdminController handles admin authentication endpoints.
type AdminController struct {
	svc *services.AdminAuthService
}

// NewAdminController constructs the admin auth controller.
func NewAdminController(svc *services.AdminAuthService) *AdminController {
	return &AdminController{svc: svc}
}

// Login handles POST /admin/login.
// Authenticates an admin and sets a refresh-token httpOnly cookie.
func (ac *AdminController) Login(c echo.Context) error {
	var req AdminLoginRequest
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

	ac.setRefreshCookie(c, refreshToken, expiresAt)

	return c.JSON(http.StatusOK, TokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   int64(time.Until(expiresAt).Seconds()),
	})
}

// Refresh handles POST /admin/refresh.
// Validates the refresh-token cookie, rotates it, and issues a new token pair.
func (ac *AdminController) Refresh(c echo.Context) error {
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

// Logout handles POST /admin/logout.
// Requires a valid JWT. Revokes all refresh tokens and clears the cookie.
func (ac *AdminController) Logout(c echo.Context) error {
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

// ChangePassword handles POST /admin/change-password.
// Requires a valid JWT. Verifies current password then updates to the new one.
func (ac *AdminController) ChangePassword(c echo.Context) error {
	userID, ok := c.Get("user_id").(uint)
	if !ok {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
	}

	var req ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "current and new passwords are required"})
	}

	if err := ac.svc.ChangePassword(userID, req.CurrentPassword, req.NewPassword); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "password changed successfully"})
}

// ─── Cookie helpers ──────────────────────────────────────────────────────────

func (ac *AdminController) setRefreshCookie(c echo.Context, token string, expiresAt time.Time) {
	c.SetCookie(&http.Cookie{Name: "admin_refresh_token", Value: token, MaxAge: int(time.Until(expiresAt).Seconds()), Path: "/", Domain: "", Secure: true, HttpOnly: true})
}

func (ac *AdminController) clearRefreshCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{Name: "admin_refresh_token", Value: "", MaxAge: -1, Path: "/", Domain: "", Secure: true, HttpOnly: true})
}
