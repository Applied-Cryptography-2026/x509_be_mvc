package db

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/your-org/x509-mvc/config"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// NewDB opens a new MySQL connection via GORM and returns it.
func NewDB() (*gorm.DB, error) {
	cfg := config.C.Database

	dsn := cfg.User + ":" + cfg.Password +
		"@tcp(" + cfg.Addr + ")/" + cfg.DBName + "?" +
		"parseTime=true&charset=utf8mb4"

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)

	return db, nil
}

// NewDBWithDSN opens a database connection using an explicit DSN string.
func NewDBWithDSN(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, err
	}
	return db, nil
}
