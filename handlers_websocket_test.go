package main

import (
	"earnit/wsmanager"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestTaskApprovalSendsNotification(t *testing.T) {
	ws := wsmanager.NewWSManager()
	childID := uint(42)

	// Gin + WebSocket test server
	router := gin.New()
	router.GET("/ws", func(c *gin.Context) {
		c.Set("user_id", childID)
		NotificationWebSocketHandler(c)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Dial as test WebSocket client
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Give server time to register connection
	time.Sleep(100 * time.Millisecond)

	// Simulate task approval
	err = ws.Notify(childID, "Task approved!")
	require.NoError(t, err)

	// Read from the client side
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "Task approved!", string(msg))
}
