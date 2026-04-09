package controllers

import (
	"github.com/labstack/echo/v4"
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

// SubmitCSRRequest is the HTTP body for submitting a CSR.
type SubmitCSRRequest struct {
	Pem string `json:"pem"`
}

// ApproveCSRRequest is the HTTP body for approving a CSR.
type ApproveCSRRequest struct {
	ApproverID uint `json:"approver_id"`
}

// RejectCSRRequest is the HTTP body for rejecting a CSR.
type RejectCSRRequest struct {
	Notes string `json:"notes"`
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// GetCSRs returns all CSRs, optionally filtered by status query param.
// GET /csrs?status=pending
func (sc *CSRController) GetCSRs(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// GetCSR returns a single CSR by ID.
// GET /csrs/:id
func (sc *CSRController) GetCSR(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// SubmitCSR parses and submits a PEM-encoded CSR.
// POST /csrs
func (sc *CSRController) SubmitCSR(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// ApproveCSR transitions a CSR to approved status.
// POST /csrs/:id/approve
func (sc *CSRController) ApproveCSR(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}

// RejectCSR transitions a CSR to rejected status.
// POST /csrs/:id/reject
func (sc *CSRController) RejectCSR(c echo.Context) error {
	// TODO: implement
	panic("TODO: implement")
}
