package main

import (
	"log"

	"earnit/models"
)

func main() {
	models.InitDB()

	tasks := []models.Task{
		{Title: "Make Your Bed", Description: "Neatly arrange your bed after waking up", Points: 5},
		{Title: "Take Out Trash", Description: "Remove trash from kitchen or bathroom", Points: 10},
		{Title: "Read for 30 Minutes", Description: "Spend time reading a book of your choice", Points: 15},
	}

	rewards := []models.Reward{
		{Title: "30 Minutes of Game Time", Description: "Play your favorite game", Cost: 30},
		{Title: "Dessert Night", Description: "Choose dessert after dinner", Cost: 25},
		{Title: "$5 Allowance", Description: "Cash reward", Cost: 50},
	}

	for _, t := range tasks {
		if err := models.DB.Create(&t).Error; err != nil {
			log.Println("Failed to seed task:", t.Title, err)
		}
	}

	for _, r := range rewards {
		if err := models.DB.Create(&r).Error; err != nil {
			log.Println("Failed to seed reward:", r.Title, err)
		}
	}

	log.Println("Seeding complete.")
}
