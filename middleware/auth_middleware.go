package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/services"
)

const (
	UserIDKey   = "user_id"
	UsernameKey = "username"
	RoleKey     = "role"
)

// JWTMiddleware creates an Echo middleware that validates Bearer access tokens
// for both admin and customer roles.
func JWTMiddleware(ts *services.TokenService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "missing authorization header")
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid authorization header format")
			}

			claims, err := ts.ValidateAccessToken(parts[1])
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired access token")
			}

			c.Set(UserIDKey, claims.UserID)
			c.Set(UsernameKey, claims.Username)
			c.Set(RoleKey, claims.Role)

			return next(c)
		}
	}
}

// AdminJWTMiddleware creates an Echo middleware that validates Bearer access tokens
// and enforces that the caller is an admin. Use this on /admin/* routes.
func AdminJWTMiddleware(ts *services.TokenService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "missing authorization header")
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid authorization header format")
			}

			claims, err := ts.ValidateAccessToken(parts[1])
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired access token")
			}

			if models.Role(claims.Role) != models.RoleAdmin {
				return echo.NewHTTPError(http.StatusForbidden, "admin access required")
			}

			c.Set(UserIDKey, claims.UserID)
			c.Set(UsernameKey, claims.Username)
			c.Set(RoleKey, claims.Role)

			return next(c)
		}
	}
}

// RefreshCookieMiddleware extracts the refresh token from the cookie and
// attaches it to the context. It does NOT validate the token.
func RefreshCookieMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("refresh_token")
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "refresh token missing")
			}
			c.Set("raw_refresh_token", cookie.Value)
			return next(c)
		}
	}
}

// AdminRefreshCookieMiddleware extracts the admin refresh token from the cookie.
func AdminRefreshCookieMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("admin_refresh_token")
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "refresh token missing")
			}
			c.Set("raw_refresh_token", cookie.Value)
			return next(c)
		}
	}
}
