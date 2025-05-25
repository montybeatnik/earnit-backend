package main

import (
	"bytes"
	"earnit/models"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupTaskTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)
	r.POST("/tasks", AuthMiddleware, CreateTask)
	r.PUT("/tasks/:id/complete", AuthMiddleware, CompleteTask)
	return r
}

func TestCreateAndCompleteTask(t *testing.T) {
	models.InitDB()
	r := setupTaskTestRouter()

	// Register parent and child
	parentEmail := "taskparent@example.com"
	childEmail := "taskchild@example.com"
	models.DB.Where("email IN (?, ?)", parentEmail, childEmail).Delete(&models.User{})

	// Register parent
	regParent := RegisterInput{
		Name:     "Parent",
		Email:    parentEmail,
		Password: "parentpass",
		Role:     "parent",
	}
	parentBody, _ := json.Marshal(regParent)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(parentBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	var regParentRes map[string]string
	json.Unmarshal(resp.Body.Bytes(), &regParentRes)
	parentToken := regParentRes["token"]

	// Get parent ID
	var parent models.User
	models.DB.Where("email = ?", parentEmail).First(&parent)

	// Register child
	regChild := RegisterInput{
		Name:     "Child",
		Email:    childEmail,
		Password: "childpass",
		Role:     "child",
		ParentID: &parent.ID,
	}
	childBody, _ := json.Marshal(regChild)
	req, _ = http.NewRequest("POST", "/register", bytes.NewBuffer(childBody))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)

	var child models.User
	models.DB.Where("email = ?", childEmail).First(&child)

	// Create task
	taskPayload := TaskInput{
		Title:        "Do Homework",
		Description:  "Math and Science",
		Points:       10,
		AssignedToID: child.ID,
	}
	taskBody, _ := json.Marshal(taskPayload)
	req, _ = http.NewRequest("POST", "/tasks", bytes.NewBuffer(taskBody))
	req.Header.Set("Authorization", "Bearer "+parentToken)
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusCreated, resp.Code)
	var taskRes map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &taskRes)
	taskData := taskRes["task"].(map[string]interface{})
	taskID := int(taskData["ID"].(float64))

	// Approve task
	req, _ = http.NewRequest("PUT", "/tasks/"+strconv.Itoa(taskID)+"/complete", nil)
	req.Header.Set("Authorization", "Bearer "+parentToken)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	var completeRes map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &completeRes)
	assert.Equal(t, "task approved", completeRes["message"])
}
