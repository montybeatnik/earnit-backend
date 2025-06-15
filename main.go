package main

import (
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"earnit/models"
	"earnit/wsmanager"

	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

func generateJWT(user models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})
	return token.SignedString(jwtKey)
}

func authMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing auth header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid claims"})
		return
	}

	// 🔥 Extract user_id directly from claims
	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid user_id in token"})
		return
	}

	// 👇 Now we’re sure user_id is set correctly
	c.Set("user_id", uint(userIDFloat))
	c.Set("role", claims["role"].(string))
	c.Next()
}

// WEB SOCKET CODE
var WebSocketClients = make(map[uint]*websocket.Conn)
var WebSocketMutex = sync.RWMutex{}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// In dev, allow any origin
		return true
	},
}

var ws = wsmanager.NewWSManager()

// WEB SOCKET CODE

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	models.InitDB(os.Getenv("DATABASE_DSN_DEV")) // TODO: change this to env variable based on env
	// models.SeedTemplates()
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:19006", "http://localhost:3000", "*"}, // Add web ports
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	r.GET("/ws", WebSocketAuthMiddleware(), NotificationWebSocketHandler)

	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)
	r.POST("/child/login", ChildLogin)
	r.POST("/check-username", CheckUsernameAvailability)

	r.GET("/task-templates", ListTaskTemplates)

	r.POST("/tasks", authMiddleware, CreateTask)

	// Public boilerplate task/reward fetch
	r.GET("/boilerplate/tasks", GetBoilerplateTasks)
	r.GET("/boilerplate/rewards", GetBoilerplateRewards)

	r.POST("/boilerplate/assign-tasks", AssignBoilerplateTasks)
	r.POST("/children/:id/setup-password", SetupChildPasswordHandler)
	r.POST("/link-parent", LinkParent)
	r.POST("/children/by-parent-code/:parentCode", GetChildrenByParentCode)

	auth := r.Group("/")
	auth.Use(AuthMiddleware())
	{
		auth.POST("/boilerplate/assign-rewards", AssignBoilerplateRewards)
		auth.GET("/me", Me)
		auth.GET("/children", ListChildren)
		auth.GET("/tasks", ListTasks)
		auth.POST("/rewards", CreateReward)
		auth.GET("/rewards", ListRewards)
		auth.POST("/rewards/:id/redeem", RedeemReward)
		auth.GET("/redemptions", ListRedemptions)
		auth.POST("/children", AddChildrenBulk)
		auth.GET("/parent/code", GetParentCode)
		auth.POST("/tasks/assign", AssignTaskFromTemplate)

		// Task routes
		auth.PUT("/tasks/:id/submit", SubmitTaskHandler)   // for children
		auth.PUT("/tasks/:id/approve", ApproveTaskHandler) // for parents
	}

	r.Run("0.0.0.0:8080") // default on :8080
}
