package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"earnit/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupTaskTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)
	r.POST("/tasks", AuthMiddleware, CreateTask)
	r.PUT("/tasks/:id/submit", AuthMiddleware, SubmitTask)
	r.PUT("/tasks/:id/complete", AuthMiddleware, CompleteTask)
	r.GET("/tasks", AuthMiddleware, ListTasks)
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
	taskID := int(taskData["id"].(float64))

	// Submit task for approval (child)
	var childToken string
	loginChild := LoginInput{
		Email:    childEmail,
		Password: "childpass",
	}
	loginBody, _ := json.Marshal(loginChild)
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	var loginRes map[string]string
	json.Unmarshal(resp.Body.Bytes(), &loginRes)
	childToken = loginRes["token"]

	req, _ = http.NewRequest("PUT", "/tasks/"+strconv.Itoa(taskID)+"/submit", nil)
	req.Header.Set("Authorization", "Bearer "+childToken)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)

	// Approve task (parent)
	req, _ = http.NewRequest("PUT", "/tasks/"+strconv.Itoa(taskID)+"/complete", nil)
	req.Header.Set("Authorization", "Bearer "+parentToken)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	var completeRes map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &completeRes)
	assert.Equal(t, "task approved", completeRes["message"])
}

func setupRewardTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)
	r.POST("/rewards", AuthMiddleware, CreateReward)
	r.GET("/rewards", AuthMiddleware, ListRewards)
	r.POST("/rewards/:id/redeem", AuthMiddleware, RedeemReward)
	r.GET("/redemptions", AuthMiddleware, ListRedemptions)
	return r
}

func TestRewardFlow(t *testing.T) {
	models.InitDB()
	r := setupRewardTestRouter()

	// Clear users
	models.DB.Where("email IN (?, ?)", "parent@example.com", "child@example.com").Delete(&models.User{})

	tests := []struct {
		name string
		run  func(t *testing.T, parentToken, childToken string)
	}{
		{
			name: "Create and redeem reward",
			run: func(t *testing.T, parentToken, childToken string) {
				// Create reward
				reward := models.Reward{
					Title:       "Ice Cream",
					Description: "One scoop from local shop",
					Cost:        5,
				}
				body, _ := json.Marshal(reward)
				req, _ := http.NewRequest("POST", "/rewards", bytes.NewBuffer(body))
				req.Header.Set("Authorization", "Bearer "+parentToken)
				req.Header.Set("Content-Type", "application/json")
				resp := httptest.NewRecorder()
				r.ServeHTTP(resp, req)
				assert.Equal(t, http.StatusCreated, resp.Code)

				// Get reward ID
				var res map[string]models.Reward
				json.Unmarshal(resp.Body.Bytes(), &res)
				rewardID := res["reward"].ID

				// Give child points
				var child models.User
				models.DB.Where("email = ?", "child@example.com").First(&child)
				child.Points = 10
				models.DB.Save(&child)

				// Redeem reward
				req, _ = http.NewRequest("POST", "/rewards/"+strconv.Itoa(int(rewardID))+"/redeem", nil)
				req.Header.Set("Authorization", "Bearer "+childToken)
				resp = httptest.NewRecorder()
				r.ServeHTTP(resp, req)
				assert.Equal(t, http.StatusOK, resp.Code)
			},
		},
	}

	// Register parent and child
	parentToken, childToken := testRegisterAndLogin(t, r)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, parentToken, childToken)
		})
	}
}

func testRegisterAndLogin(t *testing.T, r *gin.Engine) (string, string) {
	// Register parent
	regParent := RegisterInput{
		Name:     "Parent",
		Email:    "parent@example.com",
		Password: "pass",
		Role:     "parent",
	}
	parentBody, _ := json.Marshal(regParent)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(parentBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	var regParentRes map[string]string
	json.Unmarshal(resp.Body.Bytes(), &regParentRes)
	parentToken := regParentRes["token"]

	// Get parent ID
	var parent models.User
	models.DB.Where("email = ?", regParent.Email).First(&parent)

	// Register child
	regChild := RegisterInput{
		Name:     "Child",
		Email:    "child@example.com",
		Password: "pass",
		Role:     "child",
		ParentID: &parent.ID,
	}
	childBody, _ := json.Marshal(regChild)
	req, _ = http.NewRequest("POST", "/register", bytes.NewBuffer(childBody))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	var regChildRes map[string]string
	json.Unmarshal(resp.Body.Bytes(), &regChildRes)
	childToken := regChildRes["token"]

	return parentToken, childToken
}
