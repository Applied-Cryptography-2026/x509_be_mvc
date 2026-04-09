package main

import (
	"log"

	"github.com/your-org/x509-mvc/config"
	"github.com/your-org/x509-mvc/db"
	"github.com/your-org/x509-mvc/models"
)

func main() {
	config.ReadConfig()

	database, err := db.NewDB()
	if err != nil {
		log.Fatalln("migration: failed to connect to database:", err)
	}
	defer func() {
		sqlDB, _ := database.DB()
		sqlDB.Close()
	}()

	// AutoMigrate runs GORM auto-migration for all models.
	// For production use, prefer explicit SQL migration files (e.g., goose).
	err = database.AutoMigrate(
		&models.Certificate{},
		&models.CSR{},
		&models.User{},
		&models.RefreshToken{},
	)
	if err != nil {
		log.Fatalln("migration: AutoMigrate failed:", err)
	}

	log.Println("migration: all tables migrated successfully")
}
