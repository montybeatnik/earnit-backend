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

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)
	return r
}

func TestRegisterAndLogin(t *testing.T) {
	models.InitDB()
	r := setupTestRouter()

	testEmail := "testuser@example.com"
	models.DB.Where("email = ?", testEmail).Delete(&models.User{})

	regPayload := RegisterInput{
		Name:     "Test User",
		Email:    testEmail,
		Password: "password123",
		Role:     "parent",
	}
	body, _ := json.Marshal(regPayload)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	var regResult map[string]string
	json.Unmarshal(resp.Body.Bytes(), &regResult)
	assert.Contains(t, regResult, "token")

	loginPayload := LoginInput{
		Email:    testEmail,
		Password: "password123",
	}
	body, _ = json.Marshal(loginPayload)
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	var loginResult map[string]string
	json.Unmarshal(resp.Body.Bytes(), &loginResult)
	assert.Contains(t, loginResult, "token")
}

func TestDuplicateEmail(t *testing.T) {
	models.InitDB()
	r := setupTestRouter()

	testEmail := "duplicate@example.com"
	models.DB.Where("email = ?", testEmail).Delete(&models.User{})

	payload := RegisterInput{
		Name:     "Dup",
		Email:    testEmail,
		Password: "dupPass",
		Role:     "parent",
	}
	body, _ := json.Marshal(payload)

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		if i == 0 {
			assert.Equal(t, http.StatusOK, resp.Code)
		} else {
			assert.Equal(t, http.StatusInternalServerError, resp.Code)
		}
	}
}

func TestInvalidLogin(t *testing.T) {
	models.InitDB()
	r := setupTestRouter()

	payload := LoginInput{
		Email:    "wrong@example.com",
		Password: "wrongpass",
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
}
