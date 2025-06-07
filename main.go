package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"earnit/models"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	models.InitDB(os.Getenv("DATABASE_DSN_DEV")) // TODO: change this to env variable based on env
	models.SeedTemplates()
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:19006", "http://localhost:3000", "*"}, // Add web ports
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)
	r.POST("/child/login", ChildLogin)
	r.POST("/check-username", CheckUsernameAvailability)

	r.GET("/task-templates", ListTaskTemplates)

	r.GET("/tasks", authMiddleware, ListTasks)
	r.POST("/tasks", authMiddleware, CreateTask)
	r.PUT("/tasks/:id/complete", authMiddleware, CompleteTask)

	// Public boilerplate task/reward fetch
	r.GET("/boilerplate/tasks", GetBoilerplateTasks)
	r.GET("/boilerplate/rewards", GetBoilerplateRewards)

	r.POST("/boilerplate/assign-tasks", AssignBoilerplateTasks)
	r.POST("/boilerplate/assign-rewards", AssignBoilerplateRewards)
	r.POST("/children/:id/setup-password", SetupChildPasswordHandler)

	auth := r.Group("/")
	auth.Use(AuthMiddleware())
	{
		auth.GET("/me", Me)
		auth.GET("/children", ListChildren)
		auth.PUT("/tasks/:id/submit", SubmitTask)
		auth.POST("/rewards", CreateReward)
		auth.GET("/rewards", ListRewards)
		auth.POST("/rewards/:id/redeem", RedeemReward)
		auth.GET("/redemptions", ListRedemptions)
		auth.POST("/children", AddChildrenBulk)
		auth.GET("/parent/code", GetParentCode)
		auth.POST("/link-parent", LinkChildToParent)
	}

	r.Run("0.0.0.0:8080") // default on :8080
}
