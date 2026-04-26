package controllers

import (
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/middleware"
	"github.com/your-org/x509-mvc/services"
)

// KeyPairController handles HTTP requests for key pair operations.
type KeyPairController struct {
	svc *services.KeyPairService
}

// NewKeyPairController constructs a KeyPairController.
func NewKeyPairController(svc *services.KeyPairService) *KeyPairController {
	return &KeyPairController{svc: svc}
}

// GenerateRequest is the HTTP body for generating a key pair.
type GenerateRequest struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"key_size"`
}

// GetMyKeyPairs returns all key pairs owned by the authenticated customer.
// GET /customer/key-pairs
func (kc *KeyPairController) GetMyKeyPairs(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	kps, err := kc.svc.ListByOwner(userID)
	if err != nil {
		return c.JSON(500, ErrorResponse{Error: "failed to list key pairs"})
	}

	out := make([]map[string]interface{}, len(kps))
	for i, kp := range kps {
		out[i] = map[string]interface{}{
			"id":           kp.ID,
			"name":         kp.Name,
			"algorithm":    kp.Algorithm,
			"key_size":     kp.KeySize,
			"fingerprint":  kp.Fingerprint,
			"created_at":   kp.CreatedAt,
			"has_private":  true,
		}
	}
	return c.JSON(200, out)
}

// GetMyKeyPair returns a single key pair owned by the authenticated customer.
// GET /customer/key-pairs/:id
func (kc *KeyPairController) GetMyKeyPair(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid key pair id"})
	}

	kp, err := kc.svc.GetByID(uint(id))
	if err != nil {
		return c.JSON(404, ErrorResponse{Error: "key pair not found"})
	}
	if kp.OwnerID != userID {
		return c.JSON(403, ErrorResponse{Error: "access denied"})
	}

	return c.JSON(200, map[string]interface{}{
		"id":             kp.ID,
		"name":           kp.Name,
		"algorithm":      kp.Algorithm,
		"key_size":       kp.KeySize,
		"fingerprint":    kp.Fingerprint,
		"public_key_pem": kp.PublicKeyPEM,
		"created_at":     kp.CreatedAt,
	})
}

// GenerateKeyPair generates and stores a new key pair for the authenticated customer.
// POST /customer/key-pairs
func (kc *KeyPairController) GenerateKeyPair(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	var req GenerateRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid request body"})
	}

	result, err := kc.svc.Generate(&services.GenerateRequest{
		Name:      req.Name,
		Algorithm: req.Algorithm,
		KeySize:   req.KeySize,
	}, userID)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(201, map[string]interface{}{
		"id":              result.ID,
		"name":            result.Name,
		"algorithm":       result.Algorithm,
		"key_size":        result.KeySize,
		"fingerprint":     result.Fingerprint,
		"private_key_pem": result.PrivateKeyPEM,
		"created_at":      result.CreatedAt,
	})
}

// DeleteKeyPair soft-deletes a key pair owned by the authenticated customer.
// DELETE /customer/key-pairs/:id
func (kc *KeyPairController) DeleteKeyPair(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid key pair id"})
	}

	kp, err := kc.svc.GetByID(uint(id))
	if err != nil {
		return c.JSON(404, ErrorResponse{Error: "key pair not found"})
	}
	if kp.OwnerID != userID {
		return c.JSON(403, ErrorResponse{Error: "access denied"})
	}

	if err := kc.svc.Delete(uint(id), userID); err != nil {
		return c.JSON(500, ErrorResponse{Error: "failed to delete key pair"})
	}

	return c.JSON(200, map[string]string{"message": "key pair deleted"})
}

// DownloadKeyPEM returns the private key PEM as a downloadable file.
// GET /customer/key-pairs/:id/key.pem
func (kc *KeyPairController) DownloadKeyPEM(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid key pair id"})
	}

	kp, err := kc.svc.GetByID(uint(id))
	if err != nil {
		return c.JSON(404, ErrorResponse{Error: "key pair not found"})
	}
	if kp.OwnerID != userID {
		return c.JSON(403, ErrorResponse{Error: "access denied"})
	}

	if kp.PrivateKeyPEM == "" {
		return c.JSON(404, ErrorResponse{Error: "private key not available"})
	}

	// Log private key download
	kc.svc.LogKeyPairDownload(userID, kp.Name, kp.Algorithm, kp.KeySize)

	filename := kp.Name + ".key.pem"
	c.Response().Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Response().Header().Set("Content-Type", "application/x-pem-file")
	return c.Blob(200, "application/x-pem-file", []byte(kp.PrivateKeyPEM))
}
