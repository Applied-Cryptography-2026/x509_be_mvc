package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/services"
)

// AuditLogController handles audit log API endpoints
type AuditLogController struct {
	auditService *services.AuditLogService
}

// NewAuditLogController constructs AuditLogController
func NewAuditLogController(auditService *services.AuditLogService) *AuditLogController {
	return &AuditLogController{auditService: auditService}
}

// GetAuditLogs retrieves all audit logs (admin only)
// GET /admin/audit-logs?startDate=2026-01-01&endDate=2026-12-31&userEmail=admin@example.com
func (c *AuditLogController) GetAuditLogs(ctx echo.Context) error {
	// // Check admin permission
	// _, ok := ctx.Get("user").(*models.User)
	// if !ok { //|| !user.IsAdmin() {
	// 	return ctx.JSON(http.StatusForbidden, map[string]string{"error": "admin only"})
	// }

	startDate := ctx.QueryParam("startDate")
	endDate := ctx.QueryParam("endDate")
	userEmail := ctx.QueryParam("userEmail")

	var logs []*models.AuditLog
	var err error

	// Fetch logs based on filters
	if startDate != "" && endDate != "" && userEmail != "" {
		logs, err = c.auditService.GetByDateRangeAndUser(startDate, endDate, userEmail)
	} else if startDate != "" && endDate != "" {
		logs, err = c.auditService.GetByDateRange(startDate, endDate)
	} else if userEmail != "" {
		logs, err = c.auditService.GetByUserEmail(userEmail)
	} else {
		logs, err = c.auditService.GetAuditLogs()
	}

	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Convert to response format
	responses := make([]*models.AuditLogResponse, len(logs))
	for i, log := range logs {
		responses[i] = log.ToResponse()
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"data": responses,
	})
}
