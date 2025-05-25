package models

import (
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	dsn := "host=localhost user=postgres password=postgres dbname=kids_app port=5432 sslmode=disable"
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}
	DB = database
	dbAutoMigrate()
}

func dbAutoMigrate() {
	err := DB.AutoMigrate(&User{}, &Task{}, &Reward{}, &Redemption{})
	if err != nil {
		log.Fatal("Database migration failed: ", err)
	}
}

type User struct {
	ID        uint `gorm:"primaryKey"`
	Name      string
	Email     string `gorm:"unique"`
	Password  string
	Role      string // "parent" or "child"
	ParentID  *uint  // nullable if Role is "parent"
	CreatedAt time.Time
}

type Task struct {
	ID           uint `gorm:"primaryKey"`
	Title        string
	Description  string
	Points       int
	CreatedByID  uint
	AssignedToID uint
	Status       string // "pending", "approved", "rejected"
	CreatedAt    time.Time
}

type Reward struct {
	ID         uint `gorm:"primaryKey"`
	Title      string
	CostPoints int
	CreatedAt  time.Time
}

type Redemption struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint
	RewardID  uint
	Status    string // "requested", "approved", "denied"
	CreatedAt time.Time
}
