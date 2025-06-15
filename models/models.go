package models

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB(dsn string) {
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}
	DB = database
	dbAutoMigrate()
}

func dbAutoMigrate() {
	err := DB.AutoMigrate(
		&User{}, &Task{}, &Reward{}, &Redemption{}, &TaskTemplate{},
		&RewardTemplate{}, &TaskTemplate{}, &Notification{})
	if err != nil {
		log.Fatal("Database migration failed: ", err)
	}
}

func GenerateParentCode() string {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		return "000000" // fallback
	}
	return fmt.Sprintf("%x", b)[:6] // e.g., "a3f9d1"
}

func SetupChildPassword(db *gorm.DB, userID uint, username string, password string) error {
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		log.Printf("User lookup failed: %v", err)
		return err
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Password hashing failed: %v", err)
		return err
	}

	user.Username = &username
	user.Password = string(hashed)
	user.SetupComplete = true

	if err := db.Save(&user).Error; err != nil {
		log.Printf("User save failed: %v", err)
		return err
	}

	log.Printf("Password updated for user ID %d", userID)
	return nil
}

type User struct {
	gorm.Model // <- this line automatically adds ID, CreatedAt, UpdatedAt, DeletedAt

	Name          string `json:"name"`
	Email         string `gorm:"unique"`
	Password      string
	Role          string // "parent" or "child"
	CreatedAt     time.Time
	Points        int     `gorm:"default:0" json:"points"`
	SetupComplete bool    `gorm:"default:false" json:"setup_complete"`
	Code          *string `json:"code" gorm:"uniqueIndex"`
	Username      *string `gorm:"uniqueIndex;size:100" json:"username,omitempty"`

	// For child-to-parent linkage
	ParentID *uint
	Parent   *User

	// For parent-to-children linkage
	Children []User `gorm:"foreignKey:ParentID"`
}

type Task struct {
	gorm.Model             // <- this line automatically adds ID, CreatedAt, UpdatedAt, DeletedAt
	ID           uint      `json:"id"`
	Description  string    `json:"description"`
	Points       int       `json:"points"`
	Status       string    `json:"status"`
	CreatedByID  uint      `json:"created_by_id"`
	Title        string    `json:"title" `
	AssignedToID uint      `json:"assigned_to_id" binding:"required"`
	AssignedTo   User      `gorm:"foreignKey:AssignedToID" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type TaskTemplate struct {
	gorm.Model // <- this line automatically adds ID, CreatedAt, UpdatedAt, DeletedAt

	ID          uint   `json:"id"`
	Title       string `json:"title" gorm:"uniqueIndex:idx_title_assigned"`
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
	Title       string `json:"title" `
	Description string `json:"description"`
	Cost        int    `json:"cost"`
	CreatedByID uint   `json:"created_by_id"` // parent who created it
	Type        string `json:"type"`          // NEW: e.g. "screen_time", "money", "item"
}

type Redemption struct {
	gorm.Model // <- this line automatically adds ID, CreatedAt, UpdatedAt, DeletedAt

	ID       uint   `json:"id"`
	RewardID uint   `json:"reward_id"`
	ChildID  uint   `json:"child_id"`
	Status   string `json:"status"` // requested, approved, delivered
}

type RewardTemplate struct {
	ID          uint           `json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Cost        int            `json:"cost"`
	CreatedByID uint           `json:"created_by_id"`
}

func GenerateUniqueUserCode(db *gorm.DB) *string {
	for {
		code := fmt.Sprintf("%06d", rand.Intn(1000000))
		var count int64
		db.Model(&User{}).Where("code = ?", code).Count(&count)
		if count == 0 {
			return &code
		}
	}
}

type Notification struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint // who this notification is for
	Message   string
	Read      bool `gorm:"default:false"`
	CreatedAt time.Time
}
