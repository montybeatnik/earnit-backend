package models

import (
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	dsn := "host=localhost user=postgres password=postgres dbname=earnit port=5432 sslmode=disable"
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}
	DB = database
	dbAutoMigrate()
}

func dbAutoMigrate() {
	err := DB.AutoMigrate(&User{}, &Task{}, &Reward{}, &Redemption{}, &TaskTemplate{})
	if err != nil {
		log.Fatal("Database migration failed: ", err)
	}
}

type User struct {
	gorm.Model // <- this line automatically adds ID, CreatedAt, UpdatedAt, DeletedAt

	ID        uint   `gorm:"primaryKey" json:"id"`
	Name      string `json:"name"`
	Email     string `gorm:"unique"`
	Password  string
	Role      string // "parent" or "child"
	ParentID  *uint  // nullable if Role is "parent"
	CreatedAt time.Time
	Points    int `gorm:"default:0" json:"points"`
}

type Task struct {
	gorm.Model             // <- this line automatically adds ID, CreatedAt, UpdatedAt, DeletedAt
	ID           uint      `json:"id"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Points       int       `json:"points"`
	Status       string    `json:"status"`
	CreatedByID  uint      `json:"created_by_id"`
	AssignedToID uint      `json:"assigned_to_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type TaskTemplate struct {
	gorm.Model // <- this line automatically adds ID, CreatedAt, UpdatedAt, DeletedAt

	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Points      int    `json:"points"`
	CreatedByID uint   `json:"created_by_id"`
}

func SeedTemplates() {
	var count int64
	DB.Model(&TaskTemplate{}).Count(&count)
	if count == 0 {
		tasks := []TaskTemplate{
			{Title: "Make your bed", Description: "Tidy your room and make the bed", Points: 2},
			{Title: "Take out trash", Description: "Evening trash duty", Points: 3},
			{Title: "Do homework", Description: "Finish all school work", Points: 5},
		}
		for _, t := range tasks {
			DB.Create(&t)
		}
	}
}

type Reward struct {
	gorm.Model // <- this line automatically adds ID, CreatedAt, UpdatedAt, DeletedAt

	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Cost        int    `json:"cost"`
	CreatedByID uint   `json:"created_by_id"` // parent who created it
}

type Redemption struct {
	gorm.Model // <- this line automatically adds ID, CreatedAt, UpdatedAt, DeletedAt

	ID       uint   `json:"id"`
	RewardID uint   `json:"reward_id"`
	ChildID  uint   `json:"child_id"`
	Status   string `json:"status"` // requested, approved, delivered
}
