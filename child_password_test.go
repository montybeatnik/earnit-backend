package main

import (
	"bytes"
	"earnit/models"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetupChildPassword_Success(t *testing.T) {
	router := setupTestRouter()

	// Create mock child user
	child := models.User{
		Name:  "Test Child",
		Role:  "child",
		Email: "child@example.com",
	}
	models.DB.Create(&child)

	body := map[string]string{"password": "securepass"}
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/children/"+strconv.Itoa(int(child.ID))+"/setup-password", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestSetupChildPassword_InvalidID(t *testing.T) {
	router := setupTestRouter()

	body := map[string]string{"password": "securepass"}
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/children/999999/setup-password", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestSetupChildPassword_InvalidBody(t *testing.T) {
	router := setupTestRouter()

	req, _ := http.NewRequest("POST", "/children/1/setup-password", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
}
