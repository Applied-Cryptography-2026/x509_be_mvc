package repositories

import (
	"gorm.io/gorm"
)

// DBRepository wraps GORM transactions with a closure-based API.
type DBRepository struct {
	db *gorm.DB
}

// NewDBRepository constructs a DBRepository.
func NewDBRepository(db *gorm.DB) *DBRepository {
	return &DBRepository{db: db}
}

// Transaction executes fn inside a GORM database transaction.
// On any error, the transaction is rolled back. On panic, also rolled back.
// On success, the transaction is committed.
func (r *DBRepository) Transaction(
	fn func(tx *gorm.DB) (interface{}, error),
) (data interface{}, err error) {
	// TODO: implement
	panic("TODO: implement")
}
