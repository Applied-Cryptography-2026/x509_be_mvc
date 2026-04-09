package services

import (
	"net"
	"time"

	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/repositories"
)

// CSRService handles CSR-related business logic.
type CSRService struct {
	repo   *repositories.CSRRepository
	dbRepo *repositories.DBRepository
}

// NewCSRService constructs a CSRService.
func NewCSRService(
	repo *repositories.CSRRepository,
	dbRepo *repositories.DBRepository,
) *CSRService {
	return &CSRService{
		repo:   repo,
		dbRepo: dbRepo,
	}
}

// SubmitCSR parses a PEM CSR and persists it in pending state.
func (s *CSRService) SubmitCSR(pemStr string, requesterID uint) (*models.CSR, error) {
	// TODO: implement
	panic("TODO: implement")
}

// ApproveCSR transitions a CSR from pending to approved within a transaction.
func (s *CSRService) ApproveCSR(id uint, approverID uint) (*models.CSR, error) {
	// TODO: implement
	panic("TODO: implement")
}

// RejectCSR transitions a CSR from pending to rejected within a transaction.
func (s *CSRService) RejectCSR(id uint, notes string) (*models.CSR, error) {
	// TODO: implement
	panic("TODO: implement")
}

// GetCSR retrieves a single CSR by ID.
func (s *CSRService) GetCSR(id uint) (*models.CSR, error) {
	// TODO: implement
	panic("TODO: implement")
}

// ListPendingCSRs returns all CSRs awaiting approval.
func (s *CSRService) ListPendingCSRs() ([]*models.CSR, error) {
	// TODO: implement
	panic("TODO: implement")
}

// ListAllCSRs returns all CSRs.
func (s *CSRService) ListAllCSRs() ([]*models.CSR, error) {
	// TODO: implement
	panic("TODO: implement")
}

// nowFunc is injectable for testability.
var nowFunc = func() time.Time { return time.Now() }

func formatIPAddrs(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
