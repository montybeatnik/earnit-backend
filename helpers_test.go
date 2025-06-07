package main

import (
	"earnit/models"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func InitTestDB(t *testing.T, dsn string) *gorm.DB {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test db: %v", err)
	}

	// Run migrations
	err = db.AutoMigrate(
		&models.User{},
		&models.Task{},
		&models.Reward{},
		&models.Redemption{},
		&models.TaskTemplate{},
		&models.RewardTemplate{},
	)
	if err != nil {
		t.Fatalf("failed to migrate schema: %v", err)
	}

	// Optional: clear existing data
	db.Exec("TRUNCATE users, tasks, rewards, redemptions, task_templates, reward_templates RESTART IDENTITY CASCADE")

	return db
}
