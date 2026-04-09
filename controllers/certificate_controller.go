package controllers

import (
	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/services"
)

// CertificateController handles HTTP requests for certificate operations.
type CertificateController struct {
	svc *services.CertificateService
}

// NewCertificateController constructs a CertificateController.
func NewCertificateController(svc *services.CertificateService) *CertificateController {
	return &CertificateController{svc: svc}
}

// ─── HTTP Request DTOs ───────────────────────────────────────────────────────

// ImportCertificateRequest is the HTTP body for importing a certificate.
type ImportCertificateRequest struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem,omitempty"`
}

// RevokeCertificateRequest is the HTTP body for revoking a certificate.
type RevokeCertificateRequest struct {
	Reason string `json:"reason"`
}

// ValidateCertificateRequest is the HTTP body for validating a certificate.
type ValidateCertificateRequest struct {
	CertPEM string `json:"cert_pem,omitempty"`
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// GetCertificates returns all certificates.
// GET /certificates
func (cc *CertificateController) GetCertificates(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// GetCertificate returns a single certificate by ID.
// GET /certificates/:id
func (cc *CertificateController) GetCertificate(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// ImportCertificate parses and imports a PEM-encoded certificate.
// POST /certificates
func (cc *CertificateController) ImportCertificate(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// DeleteCertificate soft-deletes a certificate.
// DELETE /certificates/:id
func (cc *CertificateController) DeleteCertificate(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// RevokeCertificate marks a certificate as revoked.
// POST /certificates/:id/revoke
func (cc *CertificateController) RevokeCertificate(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// GetExpiringCertificates returns certificates expiring within a query-param window.
// GET /certificates/expiring?days=30
func (cc *CertificateController) GetExpiringCertificates(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// ValidateCertificate validates a certificate by ID or inline PEM.
// POST /certificates/validate
func (cc *CertificateController) ValidateCertificate(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}
