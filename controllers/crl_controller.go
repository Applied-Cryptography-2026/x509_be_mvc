package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/services"
)

// CRLController handles CRL generation and revocation list endpoints.
type CRLController struct {
	crlSvc *services.CRLService
}

// NewCRLController constructs a CRLController.
func NewCRLController(crlSvc *services.CRLService) *CRLController {
	return &CRLController{crlSvc: crlSvc}
}

// GenerateCRL generates a fresh X.509 CRL signed by the Root CA.
// GET /admin/crl/generate
func (cc *CRLController) GenerateCRL(c echo.Context) error {
	crl, err := cc.crlSvc.GenerateCRL()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	}

	c.Response().Header().Set("Content-Disposition", `attachment; filename="root-ca.crl.pem"`)
	c.Response().Header().Set("Content-Type", "application/x-pem-file")
	return c.Blob(http.StatusOK, "application/x-pem-file", crl.DER)
}

// GetRevokedCerts returns all revoked certificates for display.
// GET /admin/crl/revoked
func (cc *CRLController) GetRevokedCerts(c echo.Context) error {
	certs, err := cc.crlSvc.GetRevokedCerts()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to load revoked certificates"})
	}
	return c.JSON(http.StatusOK, certs)
}
