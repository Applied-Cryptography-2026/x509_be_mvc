package controllers

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/middleware"
	"github.com/your-org/x509-mvc/services"
)

// ─── HTTP Request DTOs ───────────────────────────────────────────────────────

// SubmitRevocationRequest is the HTTP body for customer revocation requests.
type SubmitRevocationRequest struct {
	CertificateID uint   `json:"certificate_id"`
	Reason        string `json:"reason"`
}

// ProcessRevocationRequest is the HTTP body for admin approve/reject.
type ProcessRevocationRequest struct {
	Notes string `json:"notes"`
}

// RevocationRequestController handles HTTP requests for revocation requests.
type RevocationRequestController struct {
	svc *services.RevocationRequestService
}

// NewRevocationRequestController constructs a RevocationRequestController.
func NewRevocationRequestController(svc *services.RevocationRequestService) *RevocationRequestController {
	return &RevocationRequestController{svc: svc}
}

// ─── Customer endpoints ────────────────────────────────────────────────────────

// SubmitRevocation handles POST /customer/revocations.
// Customer submits a revocation request for one of their certificates.
func (rc *RevocationRequestController) SubmitRevocation(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	var req SubmitRevocationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
	}
	if req.CertificateID == 0 {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "certificate_id is required"})
	}
	if req.Reason == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "reason is required"})
	}

	result, err := rc.svc.Submit(req.CertificateID, userID, req.Reason)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusCreated, result)
}

// GetMyRevocations handles GET /customer/revocations.
// Returns all revocation requests for the authenticated customer.
func (rc *RevocationRequestController) GetMyRevocations(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	reqs, err := rc.svc.ListByRequester(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to list revocation requests"})
	}

	return c.JSON(http.StatusOK, reqs)
}

// CancelRevocation handles DELETE /customer/revocations/:id.
// Customer cancels their own pending revocation request.
func (rc *RevocationRequestController) CancelRevocation(c echo.Context) error {
	userID := c.Get(middleware.UserIDKey).(uint)

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid id"})
	}

	if err := rc.svc.Cancel(uint(id), userID); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "revocation request cancelled"})
}

// ─── Admin endpoints ─────────────────────────────────────────────────────────

// GetRevocations handles GET /admin/revocations.
// Returns all revocation requests (optionally filtered by status).
func (rc *RevocationRequestController) GetRevocations(c echo.Context) error {
	status := c.QueryParam("status")

	var reqs []*services.RevocationRequestResponse
	var err error

	switch status {
	case "pending":
		reqs, err = rc.svc.ListPending()
	case "approved", "rejected":
		// For now, list all and filter (could add FindByStatus to repo)
		all, listErr := rc.svc.ListAll()
		if listErr != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to list revocation requests"})
		}
		for _, r := range all {
			if r.Status == status {
				reqs = append(reqs, r)
			}
		}
	default:
		reqs, err = rc.svc.ListAll()
	}

	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to list revocation requests"})
	}

	return c.JSON(http.StatusOK, reqs)
}

// ApproveRevocation handles POST /admin/revocations/:id/approve.
// Admin approves a revocation request and revokes the associated certificate.
func (rc *RevocationRequestController) ApproveRevocation(c echo.Context) error {
	adminID := c.Get(middleware.UserIDKey).(uint)

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid id"})
	}

	var req ProcessRevocationRequest
	c.Bind(&req) // notes is optional

	result, err := rc.svc.Approve(uint(id), adminID, req.Notes)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}

// RejectRevocation handles POST /admin/revocations/:id/reject.
// Admin rejects a revocation request.
func (rc *RevocationRequestController) RejectRevocation(c echo.Context) error {
	adminID := c.Get(middleware.UserIDKey).(uint)

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid id"})
	}

	var req ProcessRevocationRequest
	c.Bind(&req)

	result, err := rc.svc.Reject(uint(id), adminID, req.Notes)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}

// RevokeDirectly handles POST /admin/revocations/:id/revoke.
// Admin directly revokes the certificate without going through a revocation request.
func (rc *RevocationRequestController) RevokeDirectly(c echo.Context) error {
	adminID := c.Get(middleware.UserIDKey).(uint)

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid id"})
	}

	var req ProcessRevocationRequest
	c.Bind(&req)

	result, err := rc.svc.RevokeDirectly(uint(id), adminID, req.Notes)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}