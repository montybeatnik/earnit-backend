package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"earnit/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

func initDB() {
	dsn := "host=localhost user=postgres password=postgres dbname=kids_app port=5432 sslmode=disable"
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	database.AutoMigrate(&models.User{}, &models.Task{}, &models.Reward{}, &models.Redemption{})
	db = database
}

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
	claims := token.Claims.(jwt.MapClaims)
	c.Set("user_id", uint(claims["user_id"].(float64)))
	c.Set("role", claims["role"].(string))
	c.Next()
}

func main() {
	initDB()
	r := gin.Default()

	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)

	r.GET("/tasks", authMiddleware, ListTasks)
	r.POST("/tasks", authMiddleware, CreateTask)
	r.PUT("/tasks/:id/complete", authMiddleware, CompleteTask)

	r.GET("/rewards", authMiddleware, ListRewards)
	r.POST("/rewards/:id/redeem", authMiddleware, RedeemReward)

	r.Run() // default on :8080
}
