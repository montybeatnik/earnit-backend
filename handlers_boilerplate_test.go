package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"earnit/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var dsn = "postgres://postgres:postgres@localhost:5432/earnit_test?sslmode=disable"

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)
	r.POST("/rewards", AuthMiddleware(), CreateReward)
	r.POST("/tasks", AuthMiddleware(), CreateTask)
	r.PUT("/tasks/:id/submit", AuthMiddleware(), SubmitTask)
	r.PUT("/tasks/:id/complete", AuthMiddleware(), CompleteTask)
	r.POST("/rewards/:id/redeem", AuthMiddleware(), RedeemReward)
	r.GET("/boilerplate/tasks", GetBoilerplateTasks)
	r.GET("/boilerplate/rewards", GetBoilerplateRewards)
	r.POST("/children/:id/setup-password")
	return r
}

func TestGetBoilerplateTasks(t *testing.T) {
	models.DB.Exec("DELETE FROM task_templates")

	sample := models.TaskTemplate{
		Title:       "Sample Task",
		Description: "Test task",
		Points:      5,
		CreatedByID: 1,
	}
	models.DB.Create(&sample)

	router := setupTestRouter()
	req, _ := http.NewRequest("GET", "/boilerplate/tasks", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)

	var body map[string][]models.TaskTemplate
	err := json.Unmarshal(resp.Body.Bytes(), &body)
	assert.Nil(t, err)
	assert.NotEmpty(t, body["tasks"])
}

func TestGetBoilerplateRewards(t *testing.T) {
	models.InitDB(dsn)
	models.DB.Exec("DELETE FROM reward_templates")

	sample := models.RewardTemplate{
		Title:       "Sample Reward",
		Description: "Test reward",
		Cost:        10,
		CreatedByID: 1,
	}
	models.DB.Create(&sample)

	router := setupTestRouter()
	req, _ := http.NewRequest("GET", "/boilerplate/rewards", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)

	var body map[string][]models.RewardTemplate
	err := json.Unmarshal(resp.Body.Bytes(), &body)
	assert.Nil(t, err)
	assert.NotEmpty(t, body["rewards"])
}

func registerAndLogin(t *testing.T, router *gin.Engine, email, password string) string {
	// Register
	reg := map[string]string{"name": "Test User", "email": email, "password": password, "role": "parent"}
	regBody, _ := json.Marshal(reg)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(regBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)

	// Login
	login := map[string]string{"email": email, "password": password}
	loginBody, _ := json.Marshal(login)
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)

	var result map[string]string
	json.Unmarshal(resp.Body.Bytes(), &result)
	token := result["token"]
	assert.NotEmpty(t, token)

	return token
}

func setupBoilerplateTestRouter() *gin.Engine {
	r := gin.Default()
	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)

	// auth := r.Group("/", AuthMiddleware())
	// {
	r.POST("/boilerplate/tasks", AssignBoilerplateTasks)
	r.POST("/boilerplate/rewards", AssignBoilerplateRewards)
	// }

	return r
}

func TestAssignBoilerplateTasks(t *testing.T) {
	models.DB.Exec("DELETE FROM users")
	models.DB.Exec("DELETE FROM task_templates")
	models.DB.Exec("DELETE FROM tasks")

	// Create boilerplate template
	template := models.TaskTemplate{
		Title:       "Chores",
		Description: "Clean room",
		Points:      5,
		CreatedByID: 1,
	}
	models.DB.Create(&template)

	// Register + login user
	router := setupBoilerplateTestRouter()
	token := registerAndLogin(t, router, "boileruser@example.com", "password123")

	// POST to assign task
	body := map[string]interface{}{
		"task_ids": []uint{template.ID},
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/boilerplate/tasks", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)

	// Verify task created
	var tasks []models.Task
	models.DB.Find(&tasks)
	assert.Len(t, tasks, 1)
	assert.Equal(t, "Chores", tasks[0].Title)
}

func TestAssignBoilerplateRewards(t *testing.T) {
	models.DB.Exec("DELETE FROM users")
	models.DB.Exec("DELETE FROM reward_templates")
	models.DB.Exec("DELETE FROM rewards")

	// Create boilerplate template
	template := models.RewardTemplate{
		Title:       "iPad Time",
		Description: "15 mins screen time",
		Cost:        10,
		CreatedByID: 1,
	}
	models.DB.Create(&template)

	router := setupBoilerplateTestRouter()
	token := registerAndLogin(t, router, "rewarduser@example.com", "password123")

	body := map[string]interface{}{
		"reward_ids": []uint{template.ID},
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/boilerplate/rewards", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)

	// Verify reward created
	var rewards []models.Reward
	models.DB.Find(&rewards)
	assert.Len(t, rewards, 1)
	assert.Equal(t, "iPad Time", rewards[0].Title)
}
