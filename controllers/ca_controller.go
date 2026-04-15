package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/services"
)

// GenerateRootCARequest is the HTTP body for generating a Root CA.
type GenerateRootCARequest struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	Algorithm    string `json:"algorithm"` // "RSA" or "ECDSA"
	KeySize      int    `json:"key_size"`  // 2048, 4096 for RSA; 256, 384 for ECDSA
	Years        int    `json:"years"`     // validity period in years
}

// CAController handles HTTP requests for Root CA operations.
type CAController struct {
	svc *services.CAService
}

// NewCAController constructs a CAController.
func NewCAController(svc *services.CAService) *CAController {
	return &CAController{svc: svc}
}

// EnsureCA is called at startup to auto-create the Root CA if it doesn't exist.
func (cc *CAController) EnsureCA() error {
	return cc.svc.EnsureCA()
}

// GetRootCA returns the current Root CA details.
// GET /admin/root-ca
func (cc *CAController) GetRootCA(c echo.Context) error {
	rootCA, err := cc.svc.GetRootCA()
	if err != nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{Error: "Root CA not found"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"id":                    rootCA.ID,
		"subject_dn":            rootCA.Subject,
		"issuer":                rootCA.Issuer,
		"serial_number":         rootCA.Serial,
		"fingerprint":           rootCA.Fingerprint,
		"signature_algorithm":    "SHA256with" + rootCA.KeyAlgorithm,
		"not_before":            rootCA.NotBefore,
		"not_after":             rootCA.NotAfter,
		"key_algorithm":         rootCA.KeyAlgorithm,
		"key_size":              rootCA.KeySize,
		"private_key_storage":   "AES-256-GCM Encrypted",
		"is_ca":                 rootCA.IsCA,
		"status":                string(rootCA.Status),
		"created_at":            rootCA.CreatedAt,
	})
}

// GenerateRootCA generates and saves a new Root CA.
// POST /admin/root-ca/generate
func (cc *CAController) GenerateRootCA(c echo.Context) error {
	var req GenerateRootCARequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
	}

	// Defaults
	if req.CommonName == "" {
		req.CommonName = "Root CA"
	}
	if req.Organization == "" {
		req.Organization = "X509 MVC System"
	}
	if req.Country == "" {
		req.Country = "US"
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA"
	}
	if req.KeySize == 0 {
		req.KeySize = 4096
	}
	if req.Years == 0 {
		req.Years = 10
	}

	rootCA, err := cc.svc.GenerateRootCA(&services.GenerateCARequest{
		CommonName:   req.CommonName,
		Organization: req.Organization,
		Country:      req.Country,
		Algorithm:    req.Algorithm,
		KeySize:      req.KeySize,
		Years:        req.Years,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"id":                    rootCA.ID,
		"subject_dn":            rootCA.Subject,
		"serial_number":         rootCA.Serial,
		"fingerprint":           rootCA.Fingerprint,
		"signature_algorithm":   "SHA256with" + rootCA.KeyAlgorithm,
		"not_before":            rootCA.NotBefore,
		"not_after":             rootCA.NotAfter,
		"key_algorithm":         rootCA.KeyAlgorithm,
		"key_size":              rootCA.KeySize,
		"status":                string(rootCA.Status),
		"created_at":            rootCA.CreatedAt,
	})
}

// DownloadCertPEM returns the Root CA certificate PEM as a downloadable file.
// GET /admin/root-ca/cert.pem
func (cc *CAController) DownloadCertPEM(c echo.Context) error {
	certPEM, err := cc.svc.GetCertPEM()
	if err != nil {
		return c.JSON(http.StatusNotFound, ErrorResponse{Error: "Root CA not found"})
	}

	filename := "root-ca.crt"
	c.Response().Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Response().Header().Set("Content-Type", "application/x-pem-file")
	return c.Blob(http.StatusOK, "application/x-pem-file", []byte(certPEM))
}

// DownloadKeyPEM returns the Root CA private key PEM as a downloadable file.
// GET /admin/root-ca/key.pem
func (cc *CAController) DownloadKeyPEM(c echo.Context) error {
	keyPEM, err := cc.svc.GetKeyPEM()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to retrieve key PEM"})
	}

	filename := "root-ca-key.pem"
	c.Response().Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Response().Header().Set("Content-Type", "application/x-pem-file")
	return c.Blob(http.StatusOK, "application/x-pem-file", []byte(keyPEM))
}

// TLSTestResponse is the result of a TLS test run.
type TLSTestResponse struct {
	ServerCertValid bool   `json:"server_cert_valid"`
	ServerCertSignedByCA bool `json:"server_cert_signed_by_ca"`
	ClientCertValid  bool   `json:"client_cert_valid"`
	ClientCertSignedByCA bool `json:"client_cert_signed_by_ca"`
	MutualTLSEstablished bool `json:"mutual_tls_established"`
	Message          string `json:"message"`
	Error           string `json:"error,omitempty"`
}

// TestTLS runs a TLS handshake test using the Root CA to sign test certificates.
// POST /admin/root-ca/test
func (cc *CAController) TestTLS(c echo.Context) error {
	result, err := cc.svc.RunTLSTest()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	}
	return c.JSON(http.StatusOK, result)
}

