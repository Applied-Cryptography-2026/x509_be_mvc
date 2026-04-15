package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/repositories"
)

// RevocationRequestResponse is the API-facing shape for a revocation request.
type RevocationRequestResponse struct {
	ID              uint       `json:"id"`
	CertificateID   uint       `json:"certificate_id"`
	CertificateCN  string     `json:"certificate_cn,omitempty"`
	CertificateSN  string     `json:"certificate_serial,omitempty"`
	RequesterID    uint       `json:"requester_id,omitempty"`
	RequesterName  string     `json:"requester_name,omitempty"`
	Reason         string     `json:"reason"`
	Status         string     `json:"status"`
	AdminID        *uint      `json:"admin_id,omitempty"`
	AdminNotes     string     `json:"admin_notes,omitempty"`
	ProcessedAt    *time.Time `json:"processed_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// RevocationRequestService handles business logic for revocation requests.
type RevocationRequestService struct {
	revokeRepo     *repositories.RevocationRequestRepository
	certRepo       *repositories.CertificateRepository
	authRepo       *repositories.AuthRepository
}

// NewRevocationRequestService constructs a RevocationRequestService.
func NewRevocationRequestService(
	revokeRepo *repositories.RevocationRequestRepository,
	certRepo *repositories.CertificateRepository,
	authRepo *repositories.AuthRepository,
) *RevocationRequestService {
	return &RevocationRequestService{
		revokeRepo: revokeRepo,
		certRepo:   certRepo,
		authRepo:   authRepo,
	}
}

// toResponse maps a domain model to the API response.
func (s *RevocationRequestService) toResponse(req *models.RevocationRequest, certCN, certSN, requesterName string) *RevocationRequestResponse {
	return &RevocationRequestResponse{
		ID:             req.ID,
		CertificateID:  req.CertificateID,
		CertificateCN:  certCN,
		CertificateSN: certSN,
		RequesterID:   req.RequesterID,
		RequesterName: requesterName,
		Reason:        req.Reason,
		Status:        string(req.Status),
		AdminID:       req.AdminID,
		AdminNotes:    req.AdminNotes,
		ProcessedAt:   req.ProcessedAt,
		CreatedAt:     req.CreatedAt,
	}
}

// enrich adds certificate CN/SN and requester name to a response.
func (s *RevocationRequestService) enrich(r *RevocationRequestResponse) {
	// Certificate info
	if cert, err := s.certRepo.FindByID(r.CertificateID); err == nil {
		r.CertificateCN = cert.Subject
		r.CertificateSN = cert.Serial
	}
	// Requester name
	if user, err := s.authRepo.FindUserByID(r.RequesterID); err == nil {
		r.RequesterName = user.Username
	}
}

// Submit creates a new revocation request for a customer-owned certificate.
func (s *RevocationRequestService) Submit(certID, requesterID uint, reason string) (*RevocationRequestResponse, error) {
	if reason == "" {
		return nil, errors.New("reason is required")
	}

	// Verify certificate exists and belongs to the requester
	cert, err := s.certRepo.FindByID(certID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found")
	}
	if cert.RequesterID == nil || *cert.RequesterID != requesterID {
		return nil, fmt.Errorf("access denied: certificate does not belong to you")
	}
	if cert.Status == models.CertStatusRevoked {
		return nil, fmt.Errorf("certificate is already revoked")
	}

	// Check for an existing pending request
	existing, err := s.revokeRepo.FindByCertificateID(certID)
	if err == nil {
		for _, e := range existing {
			if e.Status == models.RevokeStatusPending {
				return nil, fmt.Errorf("a pending revocation request already exists for this certificate")
			}
		}
	}

	req := &models.RevocationRequest{
		CertificateID: certID,
		RequesterID:   requesterID,
		Reason:        reason,
		Status:        models.RevokeStatusPending,
		CreatedAt:     time.Now(),
	}

	created, err := s.revokeRepo.Create(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create revocation request: %w", err)
	}

	resp := &RevocationRequestResponse{
		ID:            created.ID,
		CertificateID: created.CertificateID,
		RequesterID:   created.RequesterID,
		Reason:        created.Reason,
		Status:        string(created.Status),
		CreatedAt:     created.CreatedAt,
	}
	s.enrich(resp)
	return resp, nil
}

// ListByRequester returns all revocation requests for a specific customer.
func (s *RevocationRequestService) ListByRequester(requesterID uint) ([]*RevocationRequestResponse, error) {
	reqs, err := s.revokeRepo.FindByRequesterID(requesterID)
	if err != nil {
		return nil, err
	}
	out := make([]*RevocationRequestResponse, len(reqs))
	for i, r := range reqs {
		resp := s.toResponse(r, "", "", "")
		s.enrich(resp)
		out[i] = resp
	}
	return out, nil
}

// ListPending returns all pending revocation requests for admin review.
func (s *RevocationRequestService) ListPending() ([]*RevocationRequestResponse, error) {
	reqs, err := s.revokeRepo.FindPending()
	if err != nil {
		return nil, err
	}
	out := make([]*RevocationRequestResponse, len(reqs))
	for i, r := range reqs {
		resp := s.toResponse(r, "", "", "")
		s.enrich(resp)
		out[i] = resp
	}
	return out, nil
}

// ListAll returns all revocation requests (admin view).
func (s *RevocationRequestService) ListAll() ([]*RevocationRequestResponse, error) {
	reqs, err := s.revokeRepo.FindAll()
	if err != nil {
		return nil, err
	}
	out := make([]*RevocationRequestResponse, len(reqs))
	for i, r := range reqs {
		resp := s.toResponse(r, "", "", "")
		s.enrich(resp)
		out[i] = resp
	}
	return out, nil
}

// Approve approves a revocation request and revokes the certificate.
func (s *RevocationRequestService) Approve(reqID, adminID uint, notes string) (*RevocationRequestResponse, error) {
	req, err := s.revokeRepo.FindByID(reqID)
	if err != nil {
		return nil, fmt.Errorf("revocation request not found")
	}
	if req.Status != models.RevokeStatusPending {
		return nil, fmt.Errorf("request is not pending")
	}

	// Revoke the certificate
	cert, err := s.certRepo.FindByID(req.CertificateID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found")
	}
	if cert.Status == models.CertStatusRevoked {
		return nil, fmt.Errorf("certificate is already revoked")
	}

	now := time.Now()
	cert.Status = models.CertStatusRevoked
	cert.IsRevoked = true
	cert.RevokedAt = &now
	if _, err := s.certRepo.Update(cert); err != nil {
		return nil, fmt.Errorf("failed to revoke certificate: %w", err)
	}

	// Update the request
	req.Status = models.RevokeStatusApproved
	req.AdminID = &adminID
	req.AdminNotes = notes
	req.ProcessedAt = &now
	updated, err := s.revokeRepo.Update(req)
	if err != nil {
		return nil, fmt.Errorf("failed to update request: %w", err)
	}

	resp := s.toResponse(updated, cert.Subject, cert.Serial, "")
	s.enrich(resp)
	return resp, nil
}

// Reject rejects a revocation request.
func (s *RevocationRequestService) Reject(reqID, adminID uint, notes string) (*RevocationRequestResponse, error) {
	req, err := s.revokeRepo.FindByID(reqID)
	if err != nil {
		return nil, fmt.Errorf("revocation request not found")
	}
	if req.Status != models.RevokeStatusPending {
		return nil, fmt.Errorf("request is not pending")
	}

	now := time.Now()
	req.Status = models.RevokeStatusRejected
	req.AdminID = &adminID
	req.AdminNotes = notes
	req.ProcessedAt = &now
	updated, err := s.revokeRepo.Update(req)
	if err != nil {
		return nil, fmt.Errorf("failed to update request: %w", err)
	}

	resp := s.toResponse(updated, "", "", "")
	s.enrich(resp)
	return resp, nil
}

// Cancel allows a customer to cancel their own pending revocation request.
func (s *RevocationRequestService) Cancel(reqID, requesterID uint) error {
	req, err := s.revokeRepo.FindByID(reqID)
	if err != nil {
		return fmt.Errorf("revocation request not found")
	}
	if req.RequesterID != requesterID {
		return fmt.Errorf("access denied")
	}
	if req.Status != models.RevokeStatusPending {
		return fmt.Errorf("only pending requests can be cancelled")
	}
	return s.revokeRepo.Delete(reqID)
}

// RevokeDirectly allows an admin to directly revoke a certificate without a request.
func (s *RevocationRequestService) RevokeDirectly(certID, adminID uint, reason string) (*RevocationRequestResponse, error) {
	cert, err := s.certRepo.FindByID(certID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found")
	}
	if cert.Status == models.CertStatusRevoked {
		return nil, fmt.Errorf("certificate is already revoked")
	}

	now := time.Now()
	cert.Status = models.CertStatusRevoked
	cert.IsRevoked = true
	cert.RevokedAt = &now
	if _, err := s.certRepo.Update(cert); err != nil {
		return nil, fmt.Errorf("failed to revoke certificate: %w", err)
	}

	// Create a system-generated revocation record for audit trail
	revReq := &models.RevocationRequest{
		CertificateID: certID,
		RequesterID:   adminID, // system action, admin acts as requester
		Reason:       reason,
		Status:       models.RevokeStatusApproved,
		AdminID:      &adminID,
		AdminNotes:   "Admin revoked directly",
		ProcessedAt:  &now,
		CreatedAt:    now,
	}
	created, err := s.revokeRepo.Create(revReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create revocation record: %w", err)
	}

	resp := &RevocationRequestResponse{
		ID:             created.ID,
		CertificateID:  created.CertificateID,
		RequesterID:    created.RequesterID,
		Reason:        created.Reason,
		Status:        string(created.Status),
		AdminID:       created.AdminID,
		AdminNotes:    created.AdminNotes,
		ProcessedAt:   created.ProcessedAt,
		CreatedAt:    created.CreatedAt,
	}
	s.enrich(resp)
	return resp, nil
}
