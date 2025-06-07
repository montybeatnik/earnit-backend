package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"earnit/models"

	"github.com/stretchr/testify/assert"
)

func TestRegisterAndLogin(t *testing.T) {
	models.InitDB(os.Getenv("DATABASE_DSN_TEST"))
	r := setupTestRouter()

	testEmail := fmt.Sprintf("testuser_%d@example.com", time.Now().UnixNano())
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
	models.InitDB(os.Getenv("DATABASE_DSN_TEST"))
	r := setupTestRouter()

	testEmail := fmt.Sprintf("testuser_%d@example.com", time.Now().UnixNano())
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
	models.InitDB(os.Getenv("DATABASE_DSN_TEST"))
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
