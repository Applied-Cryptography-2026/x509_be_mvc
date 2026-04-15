package controllers

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/middleware"
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

// GetMyCertificates returns certificates issued to the authenticated customer only.
// GET /customer/certificates
func (cc *CertificateController) GetMyCertificates(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	certs, err := cc.svc.ListByRequesterID(userID)
	if err != nil {
		return c.JSON(500, ErrorResponse{Error: "failed to list certificates"})
	}

	out := make([]map[string]interface{}, 0, len(certs))
	for _, cert := range certs {
		out = append(out, certToResponse(cert))
	}
	return c.JSON(200, out)
}

// GetMyCertificate returns a single certificate owned by the authenticated customer.
// GET /customer/certificates/:id
func (cc *CertificateController) GetMyCertificate(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid certificate id"})
	}

	cert, err := cc.svc.GetCertificate(uint(id))
	if err != nil {
		return c.JSON(404, ErrorResponse{Error: "certificate not found"})
	}

	// Ensure the customer owns this certificate
	if cert.RequesterID == nil || *cert.RequesterID != userID {
		return c.JSON(403, ErrorResponse{Error: "access denied"})
	}

	return c.JSON(200, certToResponse(cert))
}

// DownloadCertificate returns the PEM-encoded certificate as a downloadable file.
// GET /customer/certificates/:id/download
func (cc *CertificateController) DownloadCertificate(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid certificate id"})
	}

	cert, err := cc.svc.GetCertificate(uint(id))
	if err != nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{Error: "certificate not found"})
	}

	if cert.RequesterID == nil || *cert.RequesterID != userID {
		return c.JSON(http.StatusForbidden, ErrorResponse{Error: "access denied"})
	}

	if cert.CertPEM == "" {
		return c.JSON(http.StatusNotFound, ErrorResponse{Error: "certificate PEM not available"})
	}

	filename := "certificate.crt"
	c.Response().Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Response().Header().Set("Content-Type", "application/x-pem-file")
	return c.Blob(http.StatusOK, "application/x-pem-file", []byte(cert.CertPEM))
}

// ─── Response helpers ────────────────────────────────────────────────────────

// toUpperCaseStatus converts model status (lowercase) to API status (uppercase).
func toUpperCaseStatus(s string) string {
	switch s {
	case "active":
		return "ACTIVE"
	case "expired":
		return "EXPIRED"
	case "revoked":
		return "REVOKED"
	case "pending":
		return "PENDING"
	default:
		return s
	}
}

// certToResponse maps a service certificate model to the API response shape.
func certToResponse(cert *services.CertificateResponse) map[string]interface{} {
	return map[string]interface{}{
		"id":            cert.ID,
		"common_name":   cert.Subject,
		"subject":       cert.Subject,
		"issuer":        cert.Issuer,
		"serial_number": cert.Serial,
		"serial":        cert.Serial,
		"fingerprint":   cert.Fingerprint,
		"not_before":    cert.NotBefore,
		"not_after":     cert.NotAfter,
		"dns_names":     cert.DNSNames,
		"ip_addresses":  cert.IPAddresses,
		"is_ca":         cert.IsCA,
		"is_revoked":    cert.IsRevoked,
		"revoked_at":    cert.RevokedAt,
		"cert_pem":      cert.CertPEM,
		"requester_id":  cert.RequesterID,
		"status":        toUpperCaseStatus(string(cert.Status)),
		"key_algorithm": cert.KeyAlgorithm,
		"profile":       cert.Profile,
		"created_at":    cert.CreatedAt,
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// GetCertificates returns all certificates.
// GET /certificates  (admin) or  GET /customer/certificates  (customer)
func (cc *CertificateController) GetCertificates(c echo.Context) error {
	certs, err := cc.svc.ListCertificates()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to list certificates"})
	}

	out := make([]map[string]interface{}, 0, len(certs))
	for _, cert := range certs {
		out = append(out, certToResponse(cert))
	}
	return c.JSON(http.StatusOK, out)
}

// GetCertificate returns a single certificate by ID.
// GET /certificates/:id
func (cc *CertificateController) GetCertificate(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid certificate id"})
	}

	cert, err := cc.svc.GetCertificate(uint(id))
	if err != nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{Error: "certificate not found"})
	}

	return c.JSON(http.StatusOK, certToResponse(cert))
}

// ImportCertificate parses and imports a PEM-encoded certificate.
// POST /certificates
func (cc *CertificateController) ImportCertificate(c echo.Context) error {
	var req ImportCertificateRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
	}
	if req.CertPEM == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "cert_pem is required"})
	}

	cert, err := cc.svc.ImportCertificate(req.CertPEM, req.KeyPEM)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusCreated, certToResponse(cert))
}

// DeleteCertificate soft-deletes a certificate.
// DELETE /certificates/:id
func (cc *CertificateController) DeleteCertificate(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid certificate id"})
	}

	if err := cc.svc.DeleteCertificate(uint(id)); err != nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{Error: "certificate not found"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "certificate deleted"})
}

// DownloadAdminCertificate returns the PEM-encoded certificate as a downloadable file (admin).
// GET /admin/certificates/:id/download
func (cc *CertificateController) DownloadAdminCertificate(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid certificate id"})
	}

	cert, err := cc.svc.GetCertificate(uint(id))
	if err != nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{Error: "certificate not found"})
	}

	if cert.CertPEM == "" {
		return c.JSON(http.StatusNotFound, ErrorResponse{Error: "certificate PEM not available"})
	}

	filename := "certificate.crt"
	c.Response().Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Response().Header().Set("Content-Type", "application/x-pem-file")
	return c.Blob(http.StatusOK, "application/x-pem-file", []byte(cert.CertPEM))
}

// RevokeCertificate marks a certificate as revoked.
// POST /certificates/:id/revoke
func (cc *CertificateController) RevokeCertificate(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid certificate id"})
	}

	var req RevokeCertificateRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
	}

	cert, err := cc.svc.RevokeCertificate(uint(id), req.Reason)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, certToResponse(cert))
}

// GetExpiringCertificates returns certificates expiring within a query-param window.
// GET /certificates/expiring?days=30
func (cc *CertificateController) GetExpiringCertificates(c echo.Context) error {
	daysStr := c.QueryParam("days")
	days := 30
	if daysStr != "" {
		d, err := strconv.Atoi(daysStr)
		if err == nil && d > 0 {
			days = d
		}
	}

	certs, err := cc.svc.GetExpiringCertificates(days)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to get expiring certificates"})
	}

	out := make([]map[string]interface{}, 0, len(certs))
	for _, cert := range certs {
		out = append(out, certToResponse(cert))
	}
	return c.JSON(http.StatusOK, out)
}

// ValidateCertificate validates a certificate by inline PEM.
// POST /certificates/validate
func (cc *CertificateController) ValidateCertificate(c echo.Context) error {
	var req ValidateCertificateRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
	}
	if req.CertPEM == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "cert_pem is required"})
	}

	valid, err := cc.svc.ValidatePEM(req.CertPEM)
	if err != nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"valid":  false,
			"error":  err.Error(),
			"message": "Certificate is invalid",
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"valid":   valid,
		"message": "Certificate is valid",
	})
}
