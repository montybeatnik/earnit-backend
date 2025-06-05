package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"earnit/models"
)

func main() {
	// Load env vars for DB connection
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		log.Fatal("DATABASE_DSN is not set")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Dropping all tables...")
	err = db.Migrator().DropTable(
		&models.Task{},
		&models.Reward{},
		&models.User{},
		&models.TaskTemplate{},
		&models.RewardTemplate{},
	)
	if err != nil {
		log.Fatalf("Failed to drop tables: %v", err)
	}

	log.Println("Running AutoMigrate...")
	err = db.AutoMigrate(
		&models.Task{},
		&models.Reward{},
		&models.User{},
		&models.TaskTemplate{},
		&models.RewardTemplate{},
	)
	if err != nil {
		log.Fatalf("AutoMigrate failed: %v", err)
	}

	SeedBoilerplateTemplates(db)
	log.Println("Database reset complete.")
}

func SeedBoilerplateTemplates(db *gorm.DB) {
	tasks := []models.TaskTemplate{
		{Title: "Clean your room", Description: "Tidy up everything", Points: 10, CreatedByID: 1},
		{Title: "Feed the pet", Description: "Refill food and water", Points: 5, CreatedByID: 1},
	}

	rewards := []models.RewardTemplate{
		{Title: "Ice cream trip", Description: "Go out for dessert", Cost: 20, CreatedByID: 1},
		{Title: "Extra 15 min screen time", Description: "Bonus electronics time", Cost: 10, CreatedByID: 1},
	}

	for _, task := range tasks {
		db.Create(&task)
	}

	for _, reward := range rewards {
		db.Create(&reward)
	}
}
