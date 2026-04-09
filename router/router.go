package router

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/your-org/x509-mvc/controllers"
	authmw2 "github.com/your-org/x509-mvc/middleware"
)

// AppController holds all controllers for injection into the router.
type AppController struct {
	Certificate *controllers.CertificateController
	CSR         *controllers.CSRController
	Auth        *controllers.AuthController
	Admin       *controllers.AdminController
}

// NewRouter wires all HTTP routes and middleware to the Echo instance.
func NewRouter(
	e *echo.Echo,
	ac AppController,
	jwtMiddlewareFunc func(h echo.HandlerFunc) echo.HandlerFunc,
	adminJwtMiddlewareFunc func(h echo.HandlerFunc) echo.HandlerFunc,
) *echo.Echo {
	// Global middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(middleware.RequestID())

	// Health check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	// ═══════════════════════════════════════════════════════════════════
	// PUBLIC ROUTES — no authentication required
	// ═══════════════════════════════════════════════════════════════════

	// Customer auth
	e.POST("/auth/register", func(c echo.Context) error {
		return ac.Auth.Register(c)
	})
	e.POST("/auth/login", func(c echo.Context) error {
		return ac.Auth.Login(c)
	})

	// Admin auth
	e.POST("/admin/login", func(c echo.Context) error {
		return ac.Admin.Login(c)
	})

	// Refresh tokens
	refreshGroup := e.Group("")
	refreshGroup.Use(authmw2.RefreshCookieMiddleware())
	refreshGroup.POST("/auth/refresh", func(c echo.Context) error {
		return ac.Auth.Refresh(c)
	})

	adminRefreshGroup := e.Group("")
	adminRefreshGroup.Use(authmw2.AdminRefreshCookieMiddleware())
	adminRefreshGroup.POST("/admin/refresh", func(c echo.Context) error {
		return ac.Admin.Refresh(c)
	})

	// // ═══════════════════════════════════════════════════════════════════
	// // PROTECTED ROUTES — Customer JWT required (/customer/*)
	// // ═══════════════════════════════════════════════════════════════════
	// customer := e.Group("/customer")
	// customer.Use(jwtMiddlewareFunc)

	// // Customer auth: logout
	// customer.POST("/logout", func(c echo.Context) error {
	// 	return ac.Auth.Logout(c)
	// })

	// // CSR routes (customer submits CSRs)
	// csr := customer.Group("/csrs")
	// csr.GET("", func(c echo.Context) error { return ac.CSR.GetCSRs(c) })
	// csr.GET("/:id", func(c echo.Context) error { return ac.CSR.GetCSR(c) })
	// csr.POST("", func(c echo.Context) error { return ac.CSR.SubmitCSR(c) })

	// // Certificate routes (customer views their own)
	// cert := customer.Group("/certificates")
	// cert.GET("", func(c echo.Context) error { return ac.Certificate.GetCertificates(c) })
	// cert.GET("/:id", func(c echo.Context) error { return ac.Certificate.GetCertificate(c) })

	// // ═══════════════════════════════════════════════════════════════════
	// // PROTECTED ROUTES — Admin JWT required (/admin/*)
	// // ═══════════════════════════════════════════════════════════════════
	// admin := e.Group("/admin")
	// admin.Use(adminJwtMiddlewareFunc)

	// // Admin auth: logout and password change
	// admin.POST("/logout", func(c echo.Context) error { return ac.Admin.Logout(c) })
	// admin.POST("/change-password", func(c echo.Context) error { return ac.Admin.ChangePassword(c) })

	// // Certificate management
	// adminCert := admin.Group("/certificates")
	// adminCert.GET("", func(c echo.Context) error { return ac.Certificate.GetCertificates(c) })
	// adminCert.GET("/:id", func(c echo.Context) error { return ac.Certificate.GetCertificate(c) })
	// adminCert.POST("", func(c echo.Context) error { return ac.Certificate.ImportCertificate(c) })
	// adminCert.DELETE("/:id", func(c echo.Context) error { return ac.Certificate.DeleteCertificate(c) })
	// adminCert.POST("/:id/revoke", func(c echo.Context) error { return ac.Certificate.RevokeCertificate(c) })
	// adminCert.GET("/expiring", func(c echo.Context) error { return ac.Certificate.GetExpiringCertificates(c) })
	// adminCert.POST("/validate", func(c echo.Context) error { return ac.Certificate.ValidateCertificate(c) })

	// // CSR management (admin approves/rejects)
	// adminCSR := admin.Group("/csrs")
	// adminCSR.GET("", func(c echo.Context) error { return ac.CSR.GetCSRs(c) })
	// adminCSR.GET("/:id", func(c echo.Context) error { return ac.CSR.GetCSR(c) })
	// adminCSR.POST("/:id/approve", func(c echo.Context) error { return ac.CSR.ApproveCSR(c) })
	// adminCSR.POST("/:id/reject", func(c echo.Context) error { return ac.CSR.RejectCSR(c) })

	return e
}
