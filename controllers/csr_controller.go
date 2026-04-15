package controllers

import (
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/middleware"
	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/services"
)

// CSRController handles HTTP requests for CSR operations.
type CSRController struct {
	svc *services.CSRService
}

// NewCSRController constructs a CSRController.
func NewCSRController(svc *services.CSRService) *CSRController {
	return &CSRController{svc: svc}
}

// ─── HTTP Request DTOs ───────────────────────────────────────────────────────

// HttpSubmitCSRRequest is the HTTP body for submitting a CSR.
type HttpSubmitCSRRequest struct {
	CommonName   string   `json:"common_name"`
	DNSNames     []string `json:"dns_names"`
	IPAddresses  []string `json:"ip_addresses"`
	KeyAlgorithm string   `json:"key_algorithm"`
	KeyPairID    uint     `json:"key_pair_id"`
}

// ApproveCSRRequest is the HTTP body for approving a CSR.
type ApproveCSRRequest struct {
	ApproverID uint `json:"approver_id"`
}

// RejectCSRRequest is the HTTP body for rejecting a CSR.
type RejectCSRRequest struct {
	Notes string `json:"notes"`
}

// ─── Response helpers ────────────────────────────────────────────────────────

func csrStatusUpper(s models.CSRStatus) string {
	switch s {
	case models.CSRStatusPending:
		return "PENDING"
	case models.CSRStatusApproved:
		return "APPROVED"
	case models.CSRStatusRejected:
		return "REJECTED"
	case models.CSRStatusIssued:
		return "ISSUED"
	default:
		return string(s)
	}
}

func csrToResponse(csr *models.CSR) map[string]interface{} {
	return map[string]interface{}{
		"id":                  csr.ID,
		"common_name":          csr.Subject,
		"subject":              csr.Subject,
		"pem":                 csr.Pem,
		"key_algorithm":        csr.KeyAlgorithm,
		"signature_algorithm":   csr.SignatureAlgorithm,
		"dns_names":            csr.DNSNames,
		"ip_addresses":         csr.IPAddresses,
		"status":              csrStatusUpper(csr.Status),
		"approved_at":          csr.ApprovedAt,
		"rejected_at":          csr.RejectedAt,
		"approver_id":          csr.ApproverID,
		"notes":               csr.Notes,
		"requester_id":         csr.RequesterID,
		"key_pair_id":          csr.KeyPairID,
		"created_at":           csr.CreatedAt,
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// GetCSRs returns all CSRs, optionally filtered by status query param.
// For /customer/csrs → returns only the requesting user's CSRs.
// For /admin/csrs    → returns all CSRs.
func (sc *CSRController) GetCSRs(c echo.Context) error {
	var csrs []*models.CSR
	var err error

	status := c.QueryParam("status")

	// If this is a customer route (checked via role), return only their CSRs
	role := c.Get(middleware.RoleKey)
	if role == string(models.RoleCustomer) {
		userID := c.Get(middleware.UserIDKey).(uint)
		csrs, err = sc.svc.ListByRequesterID(userID)
	} else {
		// Admin route — return all CSRs
		if status != "" {
			switch status {
			case "pending":
				csrs, err = sc.svc.ListPendingCSRs()
			default:
				csrs, err = sc.svc.ListAllCSRs()
			}
		} else {
			csrs, err = sc.svc.ListAllCSRs()
		}
	}

	if err != nil {
		return c.JSON(500, ErrorResponse{Error: "failed to list CSRs"})
	}

	out := make([]map[string]interface{}, len(csrs))
	for i, csr := range csrs {
		out[i] = csrToResponse(csr)
	}
	return c.JSON(200, out)
}

// GetCSR returns a single CSR by ID.
// GET /csrs/:id
func (sc *CSRController) GetCSR(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid CSR id"})
	}

	csr, err := sc.svc.GetCSRByID(uint(id))
	if err != nil {
		return c.JSON(404, ErrorResponse{Error: "CSR not found"})
	}

	return c.JSON(200, csrToResponse(csr))
}

// SubmitCSR creates a new CSR for the authenticated customer.
// POST /csrs  (customer route)
func (sc *CSRController) SubmitCSR(c echo.Context) error {
	var req HttpSubmitCSRRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid request body"})
	}
	if req.CommonName == "" {
		return c.JSON(400, ErrorResponse{Error: "common_name is required"})
	}
	if req.KeyPairID == 0 {
		return c.JSON(400, ErrorResponse{Error: "key_pair_id is required — select a key pair first"})
	}

	userID := c.Get(middleware.UserIDKey).(uint)

	svcReq := &services.SubmitCSRRequest{
		CommonName:   req.CommonName,
		DNSNames:     req.DNSNames,
		IPAddresses:  req.IPAddresses,
		KeyAlgorithm: req.KeyAlgorithm,
		KeyPairID:    req.KeyPairID,
	}

	csr, err := sc.svc.SubmitCSR(svcReq, userID)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(201, csrToResponse(csr))
}

// ApproveCSR transitions a CSR to approved and issues a certificate.
// POST /csrs/:id/approve
func (sc *CSRController) ApproveCSR(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid CSR id"})
	}

	var req ApproveCSRRequest
	c.Bind(&req) // body is optional

	// Use admin's own ID if not provided
	approverID := c.Get(middleware.UserIDKey).(uint)
	if req.ApproverID != 0 {
		approverID = req.ApproverID
	}

	csr, err := sc.svc.ApproveCSR(uint(id), approverID)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(200, csrToResponse(csr))
}

// RejectCSR transitions a CSR to rejected status.
// POST /csrs/:id/reject
func (sc *CSRController) RejectCSR(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid CSR id"})
	}

	var req RejectCSRRequest
	c.Bind(&req) // notes are optional

	csr, err := sc.svc.RejectCSR(uint(id), req.Notes)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(200, csrToResponse(csr))
}

// DownloadCSR returns the CSR PEM as a downloadable file.
// GET /csrs/:id/download
func (sc *CSRController) DownloadCSR(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(400, ErrorResponse{Error: "invalid CSR id"})
	}

	csr, err := sc.svc.GetCSRByID(uint(id))
	if err != nil {
		return c.JSON(404, ErrorResponse{Error: "CSR not found"})
	}

	if csr.Pem == "" {
		return c.JSON(404, ErrorResponse{Error: "CSR PEM not available"})
	}

	filename := "csr.pem"
	c.Response().Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Response().Header().Set("Content-Type", "application/x-pem-file")
	return c.Blob(200, "application/x-pem-file", []byte(csr.Pem))
}
