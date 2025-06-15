package wsmanager

import (
	"sync"

	"github.com/gorilla/websocket"
)

var conns = struct {
	sync.RWMutex
	connections map[uint]*websocket.Conn
}{
	connections: make(map[uint]*websocket.Conn),
}

func Register(userID uint, conn *websocket.Conn) {
	conns.Lock()
	defer conns.Unlock()
	conns.connections[userID] = conn
}

func Notify(userID uint, message string) error {
	conns.RLock()
	defer conns.RUnlock()
	if conn, ok := conns.connections[userID]; ok {
		return conn.WriteMessage(websocket.TextMessage, []byte(message))
	}
	return nil
}
