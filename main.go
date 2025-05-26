package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"earnit/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
	claims := token.Claims.(jwt.MapClaims)
	c.Set("user_id", uint(claims["user_id"].(float64)))
	c.Set("role", claims["role"].(string))
	c.Next()
}

func main() {
	models.InitDB()
	models.SeedTemplates()
	r := gin.Default()

	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)

	r.GET("/me", AuthMiddleware, Me)

	r.GET("/children", AuthMiddleware, ListChildren)

	r.GET("/task-templates", ListTaskTemplates)

	r.GET("/tasks", authMiddleware, ListTasks)
	r.POST("/tasks", authMiddleware, CreateTask)
	r.PUT("/tasks/:id/submit", AuthMiddleware, SubmitTask)
	r.PUT("/tasks/:id/complete", authMiddleware, CompleteTask)

	r.POST("/rewards", AuthMiddleware, CreateReward)
	r.GET("/rewards", AuthMiddleware, ListRewards)
	r.POST("/rewards/:id/redeem", AuthMiddleware, RedeemReward)
	r.GET("/redemptions", AuthMiddleware, ListRedemptions)

	r.Run() // default on :8080
}
