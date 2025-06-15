package wsmanager

import (
	"fmt"
	"log"
	"sync"

	"github.com/gorilla/websocket"
)

type WSManager struct {
	mu          sync.RWMutex
	connections map[uint][]*websocket.Conn
	roles       map[uint]string // maps userID to role (e.g. "parent" or "child")
}

func NewWSManager() *WSManager {
	return &WSManager{
		connections: make(map[uint][]*websocket.Conn),
		roles:       make(map[uint]string),
	}
}

func roleLabel(userID uint, role string) string {
	if role == "" {
		if userID == 1 {
			return "[PARENT? userID=1]"
		} else if userID == 2 {
			return "[CHILD? userID=2]"
		}
		return fmt.Sprintf("[userID=%d]", userID)
	}
	return fmt.Sprintf("[%s userID=%d]", role, userID)
}

// Register adds a WebSocket connection for the given user
func (w *WSManager) Register(userID uint, conn *websocket.Conn, role string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.roles[userID] = role
	w.connections[userID] = append(w.connections[userID], conn)

	log.Printf("✅ Registered WebSocket %s (total connections: %d)", roleLabel(userID, role), len(w.connections[userID]))
}

// Unregister removes a specific connection for the user
func (w *WSManager) Unregister(userID uint, conn *websocket.Conn) {
	w.mu.Lock()
	defer w.mu.Unlock()

	conns := w.connections[userID]
	for i, c := range conns {
		if c == conn {
			w.connections[userID] = append(conns[:i], conns[i+1:]...)
			log.Printf("🚪 Unregistered WebSocket %s", roleLabel(userID, w.roles[userID]))
			break
		}
	}

	if len(w.connections[userID]) == 0 {
		delete(w.connections, userID)
		delete(w.roles, userID)
	}
}

// Notify sends a message to all of a user's active WebSocket connections
func (w *WSManager) Notify(userID uint, message string) error {
	w.mu.RLock()
	conns := w.connections[userID]
	role := w.roles[userID]
	w.mu.RUnlock()

	if len(conns) == 0 {
		log.Printf("❌ No active WebSocket connections for %s", roleLabel(userID, role))
		return fmt.Errorf("no connections for user %d", userID)
	}

	log.Printf("📨 Notifying %s with message: %s", roleLabel(userID, role), message)

	for _, conn := range conns {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			log.Printf("⚠️ Error sending to %s: %v", roleLabel(userID, role), err)
		}
	}

	return nil
}
