package main

import (
	"earnit/wsmanager"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestTaskApprovalSendsNotification(t *testing.T) {
	// Simulate child user connecting
	childID := uint(42)

	// Gin + WebSocket test server
	router := gin.New()
	router.GET("/ws", func(c *gin.Context) {
		c.Set("user_id", childID)
		NotificationWebSocketHandler(c)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	wsURL := "ws" + ts.URL[len("http"):] + "/ws"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer ws.Close()

	// Simulate task approval
	err = wsmanager.Notify(childID, "Task approved!")
	require.NoError(t, err)

	// Verify child received it
	_, msg, err := ws.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "Task approved!", string(msg))
}
