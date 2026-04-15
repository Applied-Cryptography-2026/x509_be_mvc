package main

import (
	"fmt"
	"log"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/config"
	"github.com/your-org/x509-mvc/controllers"
	"github.com/your-org/x509-mvc/db"
	"github.com/your-org/x509-mvc/middleware"
	"github.com/your-org/x509-mvc/repositories"
	"github.com/your-org/x509-mvc/router"
	"github.com/your-org/x509-mvc/services"
	"gorm.io/gorm"
)

func main() {
	// 1. Load YAML configuration
	config.ReadConfig()

	// 2. Open database connection
	database, err := db.NewDB()
	if err != nil {
		log.Fatalln("app: failed to open database:", err)
	}
	defer func() {
		sqlDB, _ := database.DB()
		sqlDB.Close()
	}()

	// 3. Build the DI composition root
	ac := buildAppController(database)

	// 3b. Auto-create Root CA if it doesn't exist
	if err := ac.CA.EnsureCA(); err != nil {
		log.Fatalln("app: failed to ensure Root CA:", err)
	}

	// 4. Bootstrap Echo HTTP framework
	e := echo.New()

	// 5. Wire routes with role-based auth middleware
	jwtMw := buildJWTMiddleware()
	adminJwtMw := buildAdminJWTMiddleware()
	e = router.NewRouter(e, ac, jwtMw, adminJwtMw)

	// 6. Start the HTTP server
	addr := ":" + config.C.Server.Address
	fmt.Println("x509-mvc server listening at http://localhost" + addr)
	if err := e.Start(addr); err != nil {
		log.Fatalln("app: server failed:", err)
	}
}

// ─── Wiring / Composition Root ─────────────────────────────────────────────────

func buildAppController(database *gorm.DB) router.AppController {
	// ─── Repositories ──────────────────────────────────────────────────────────
	certRepo := repositories.NewCertificateRepository(database)
	csrRepo := repositories.NewCSRRepository(database)
	authRepo := repositories.NewAuthRepository(database)
	dbRepo := repositories.NewDBRepository(database)
	keyPairRepo := repositories.NewKeyPairRepository(database)
	revokeRepo := repositories.NewRevocationRequestRepository(database)

	// ─── Services ──────────────────────────────────────────────────────────────
	converter := services.NewConverter()

	certSvc := services.NewCertificateService(
		certRepo, dbRepo, converter,
	)

	caSvc := services.NewCAService(certRepo)
	caCtrl := controllers.NewCAController(caSvc)
	csrSvc := services.NewCSRService(csrRepo, certRepo, caSvc, keyPairRepo)

	tokenCfg := services.JWTConfig{
		AccessTokenSecret:  config.C.JWT.AccessTokenSecret,
		RefreshTokenSecret: config.C.JWT.RefreshTokenSecret,
		AccessTokenTTL:     time.Duration(config.C.JWT.AccessTokenTTL) * time.Minute,
		RefreshTokenTTL:    time.Duration(config.C.JWT.RefreshTokenTTL) * 24 * time.Hour,
		Issuer:             config.C.JWT.Issuer,
	}
	tokenSvc := services.NewTokenService(tokenCfg)
	hasher := services.NewHasher()

	customerAuthSvc := services.NewCustomerAuthService(authRepo, tokenSvc, hasher)
	adminAuthSvc := services.NewAdminAuthService(authRepo, tokenSvc, hasher)

	keyPairSvc := services.NewKeyPairService(keyPairRepo)
	keyPairCtrl := controllers.NewKeyPairController(keyPairSvc)

	revokeSvc := services.NewRevocationRequestService(revokeRepo, certRepo, authRepo)
	revokeCtrl := controllers.NewRevocationRequestController(revokeSvc)

	crlSvc := services.NewCRLService(certRepo, keyPairRepo)
	crlCtrl := controllers.NewCRLController(crlSvc)

	// ─── Controllers ───────────────────────────────────────────────────────────
	certCtrl := controllers.NewCertificateController(certSvc)
	csrCtrl := controllers.NewCSRController(csrSvc)
	authCtrl := controllers.NewAuthController(customerAuthSvc)
	adminCtrl := controllers.NewAdminController(adminAuthSvc)

	return router.AppController{
		Certificate:       certCtrl,
		CSR:               csrCtrl,
		Auth:              authCtrl,
		Admin:             adminCtrl,
		CA:                caCtrl,
		KeyPair:           keyPairCtrl,
		RevocationRequest: revokeCtrl,
		CRL:               crlCtrl,
	}
}

func buildJWTMiddleware() func(h echo.HandlerFunc) echo.HandlerFunc {
	tokenCfg := services.JWTConfig{
		AccessTokenSecret:  config.C.JWT.AccessTokenSecret,
		RefreshTokenSecret: config.C.JWT.RefreshTokenSecret,
		AccessTokenTTL:     time.Duration(config.C.JWT.AccessTokenTTL) * time.Minute,
		RefreshTokenTTL:    time.Duration(config.C.JWT.RefreshTokenTTL) * 24 * time.Hour,
		Issuer:             config.C.JWT.Issuer,
	}
	tokenSvc := services.NewTokenService(tokenCfg)
	return func(h echo.HandlerFunc) echo.HandlerFunc {
		return middleware.JWTMiddleware(tokenSvc)(h)
	}
}

func buildAdminJWTMiddleware() func(h echo.HandlerFunc) echo.HandlerFunc {
	tokenCfg := services.JWTConfig{
		AccessTokenSecret:  config.C.JWT.AccessTokenSecret,
		RefreshTokenSecret: config.C.JWT.RefreshTokenSecret,
		AccessTokenTTL:     time.Duration(config.C.JWT.AccessTokenTTL) * time.Minute,
		RefreshTokenTTL:    time.Duration(config.C.JWT.RefreshTokenTTL) * 24 * time.Hour,
		Issuer:             config.C.JWT.Issuer,
	}
	tokenSvc := services.NewTokenService(tokenCfg)
	return func(h echo.HandlerFunc) echo.HandlerFunc {
		return middleware.AdminJWTMiddleware(tokenSvc)(h)
	}
}
