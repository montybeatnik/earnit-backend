package main

import (
	"log"
	"os"

	"earnit/models"
	"earnit/utils"
)

func SeedTestUsers() {
	if os.Getenv("APP_ENV") != "dev" {
		return
	}

	// --- Seed Parent ---
	var parent models.User
	if err := models.DB.Where("email = ?", "parent@test.com").First(&parent).Error; err != nil {
		log.Println("Seeding test parent user...")
		passwordHash, _ := utils.HashPassword("test123")
		models.DB.Create(&models.User{
			Name:     "Dev Parent",
			Email:    "parent@test.com",
			Password: passwordHash,
			Role:     "parent",
		})
	}

	// --- Seed Child ---
	var child models.User
	if err := models.DB.Where("email = ?", "child@test.com").First(&child).Error; err != nil {
		log.Println("Seeding test child user...")
		passwordHash, _ := utils.HashPassword("test123")
		models.DB.Create(&models.User{
			Name:     "Dev Child",
			Email:    "child@test.com",
			Password: passwordHash,
			Role:     "child",
		})
	}

	// --- Re-fetch to get correct IDs ---
	if err := models.DB.Where("email = ?", "parent@test.com").First(&parent).Error; err != nil {
		log.Fatal("Failed to reload parent:", err)
	}
	if err := models.DB.Where("email = ?", "child@test.com").First(&child).Error; err != nil {
		log.Fatal("Failed to reload child:", err)
	}

	// --- Link child to parent ---
	child.ParentID = &parent.ID
	if err := models.DB.Save(&child).Error; err != nil {
		log.Println("❌ Failed to link test child to parent:", err)
	} else {
		log.Println("✅ Linked test child to test parent")
	}

	// --- Seed Tasks (assign to child) ---
	tasks := []models.Task{
		{
			Title:        "Make Your Bed",
			Description:  "Neatly arrange your bed after waking up",
			Points:       5,
			Status:       "incomplete",
			CreatedByID:  parent.ID,
			AssignedToID: child.ID,
		},
		{
			Title:        "Take Out Trash",
			Description:  "Remove trash from kitchen or bathroom",
			Points:       10,
			Status:       "incomplete",
			CreatedByID:  parent.ID,
			AssignedToID: child.ID,
		},
		{
			Title:        "Read for 30 Minutes",
			Description:  "Spend time reading a book of your choice",
			Points:       15,
			Status:       "incomplete",
			CreatedByID:  parent.ID,
			AssignedToID: child.ID,
		},
	}

	for _, t := range tasks {
		if err := models.DB.Create(&t).Error; err != nil {
			log.Println("Failed to seed task:", t.Title, err)
		} else {
			log.Println("✅ Seeded task:", t.Title)
		}
	}

	// --- Seed Rewards (optional, not child-specific) ---
	rewards := []models.Reward{
		{Title: "30 Minutes of Game Time", Description: "Play your favorite game", Cost: 30},
		{Title: "Dessert Night", Description: "Choose dessert after dinner", Cost: 25},
		{Title: "$5 Allowance", Description: "Cash reward", Cost: 50},
	}

	for _, r := range rewards {
		if err := models.DB.Create(&r).Error; err != nil {
			log.Println("Failed to seed reward:", r.Title, err)
		} else {
			log.Println("✅ Seeded reward:", r.Title)
		}
	}

	log.Println("Seeding complete.")
}

func main() {
	models.InitDB(os.Getenv("DATABASE_DSN_DEV"))
	SeedTestUsers()
}
