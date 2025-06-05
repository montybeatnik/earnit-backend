package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"earnit/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func testRegisterLoginWithIDs(router *gin.Engine, name, role string, parentID *uint) (token, email string, id uint) {
	email = fmt.Sprintf("%s_%d@example.com", role, time.Now().UnixNano())
	body := map[string]interface{}{
		"name":     name,
		"email":    email,
		"password": "password123",
		"role":     role,
	}
	if parentID != nil {
		body["parent_id"] = *parentID
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		log.Fatalf("Failed to register %s: %s", role, w.Body.String())
	}

	var resp struct {
		Token string `json:"token"`
		ID    uint   `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	return resp.Token, email, resp.ID
}

func assignChildToParent(childID uint, parentID uint) {
	var child models.User
	if err := models.DB.First(&child, childID).Error; err != nil {
		log.Fatal("Child not found")
	}
	child.ParentID = &parentID
	models.DB.Save(&child)
}

func createTaskForChild(router *gin.Engine, token string, childID uint) uint {
	task := map[string]interface{}{
		"title":          "Do Homework",
		"description":    "Complete your homework",
		"points":         10,
		"assigned_to_id": childID,
	}
	jsonBody, _ := json.Marshal(task)

	fmt.Printf("DEBUG: Creating task for child ID: %d\n", childID)
	req := httptest.NewRequest("POST", "/tasks", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		log.Fatalf("Failed to create task: %s", w.Body.String())
	}

	var resp struct {
		Task models.Task `json:"task"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	return resp.Task.ID
}

func TestRewardFlow(t *testing.T) {
	r := setupTestRouter()

	t.Run("Create and redeem reward", func(t *testing.T) {
		parentToken, _, parentID := testRegisterLoginWithIDs(r, "Parent", "parent", nil)
		childToken, _, childID := testRegisterLoginWithIDs(r, "Child", "child", &parentID)

		assignChildToParent(childID, parentID)
		taskID := createTaskForChild(r, parentToken, childID)

		// Child submits the task
		req := httptest.NewRequest("PUT", fmt.Sprintf("/tasks/%d/submit", taskID), nil)
		req.Header.Set("Authorization", "Bearer "+childToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Parent approves the task
		req = httptest.NewRequest("PUT", fmt.Sprintf("/tasks/%d/complete", taskID), nil)
		req.Header.Set("Authorization", "Bearer "+parentToken)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Parent creates reward
		reward := map[string]interface{}{
			"title":  "Extra TV Time",
			"cost":   5,
			"status": "available",
		}
		rewardBody, _ := json.Marshal(reward)
		req = httptest.NewRequest("POST", "/rewards", bytes.NewBuffer(rewardBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+parentToken)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)

		var resp struct {
			Reward models.Reward `json:"reward"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)

		// Child redeems reward
		req = httptest.NewRequest("POST", fmt.Sprintf("/rewards/%d/redeem", resp.Reward.ID), nil)
		req.Header.Set("Authorization", "Bearer "+childToken)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
