package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"earnit/models"
	"earnit/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

func GenerateJWT(user models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})
	return token.SignedString(jwtKey)
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
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
			log.Printf("invalid token: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid claims"})
			return
		}

		// 🔥 Extract user_id from the token claims
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid user_id in token"})
			return
		}
		role, _ := claims["role"].(string)

		c.Set("user_id", uint(userIDFloat))
		c.Set("role", role)
		c.Next()
	}
}

type RegisterResponse struct {
	Token string `json:"token"`
	ID    uint   `json:"id"`
}

func RegisterUser(router *gin.Engine, name, role string) (string, string, uint) {
	email := fmt.Sprintf("%s_%d@example.com", role, time.Now().UnixNano())
	password := "password123"

	body := map[string]string{
		"name":     name,
		"email":    email,
		"password": password,
		"role":     role,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		panic(fmt.Sprintf("Failed to register %s: %s", role, w.Body.String()))
	}

	var resp RegisterResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	return resp.Token, email, resp.ID
}

type RegisterInput struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required,oneof=parent child"`
	ParentID *uint  `json:"parent_id"`
}

type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func RegisterHandler(c *gin.Context) {
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}
	user := models.User{
		Name:     input.Name,
		Email:    input.Email,
		Password: string(hashedPassword),
		Role:     input.Role,
		ParentID: input.ParentID,
	}
	if err := models.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}
	log.Printf("generating token for %v\n", user.Name)
	token, err := GenerateJWT(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"id":    user.ID,
	})
}

func SetupStarterContent(c *gin.Context) {
	userID := c.GetUint("user_id")
	role := c.GetString("role")

	if role == "parent" {
		starterTasks := []models.Task{
			{Title: "Take out trash", Points: 5, CreatedByID: userID},
			{Title: "Do homework", Points: 10, CreatedByID: userID},
		}

		starterRewards := []models.Reward{
			{Title: "30 min of screen time", Cost: 15, CreatedByID: userID},
			{Title: "$5 allowance", Cost: 50, CreatedByID: userID},
		}

		for _, task := range starterTasks {
			models.DB.Create(&task)
		}
		for _, reward := range starterRewards {
			models.DB.Create(&reward)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Starter content created!"})
}

// GET /boilerplate/tasks
func ListBoilerplateTasks(c *gin.Context) {
	var tasks []models.TaskTemplate
	models.DB.Find(&tasks)
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

func GetBoilerplateTasks(c *gin.Context) {
	var tasks []models.TaskTemplate
	models.DB.Find(&tasks)
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

func GetBoilerplateRewards(c *gin.Context) {
	var rewards []models.RewardTemplate
	models.DB.Find(&rewards)
	c.JSON(http.StatusOK, gin.H{"rewards": rewards})
}

type AssignBoilerplateInput struct {
	TaskIDs   []uint `json:"task_ids"`
	RewardIDs []uint `json:"reward_ids"`
}

func AssignBoilerplate(c *gin.Context) {
	var input AssignBoilerplateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	userID := c.GetUint("user_id")

	for _, tid := range input.TaskIDs {
		var t models.TaskTemplate
		if err := models.DB.First(&t, tid).Error; err == nil {
			models.DB.Create(&models.Task{
				Title:       t.Title,
				Description: t.Description,
				Points:      t.Points,
				Status:      "pending",
				CreatedByID: userID,
			})
		}
	}

	for _, rid := range input.RewardIDs {
		var r models.RewardTemplate
		if err := models.DB.First(&r, rid).Error; err == nil {
			models.DB.Create(&models.Reward{
				Title:       r.Title,
				Description: r.Description,
				Cost:        r.Cost,
				CreatedByID: userID,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Boilerplate assigned"})
}

// POST /boilerplate/assign-tasks
func AssignSelectedTasks(c *gin.Context) {
	var input struct {
		TaskIDs []uint `json:"task_ids"`
	}
	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	userID := c.GetUint("user_id")
	for _, tid := range input.TaskIDs {
		var tmpl models.TaskTemplate
		if err := models.DB.First(&tmpl, tid).Error; err == nil {
			models.DB.Create(&models.Task{
				Title:       tmpl.Title,
				Description: tmpl.Description,
				Points:      tmpl.Points,
				Status:      "pending",
				CreatedByID: userID,
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Tasks assigned"})
}

func LoginHandler(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var user models.User
	if err := models.DB.Where("email = ?", input.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	token, err := GenerateJWT(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func Me(c *gin.Context) {
	userID := c.GetUint("user_id")
	var user models.User
	if err := models.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}

func ListChildren(c *gin.Context) {
	userID := c.GetUint("user_id")
	var children []models.User
	models.DB.Where("parent_id = ?", userID).Find(&children)
	log.Printf("looking for the child of %v\n", userID)
	c.JSON(http.StatusOK, gin.H{"children": children})
	log.Print(children)
}

func ListTaskTemplates(c *gin.Context) {
	var templates []models.TaskTemplate
	models.DB.Find(&templates)
	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

type TaskInput struct {
	Title        string `json:"title" binding:"required"`
	Description  string `json:"description"`
	Points       int    `json:"points" binding:"required,min=1"`
	AssignedToID uint   `json:"assigned_to_id" binding:"required"`
}

func CreateTask(c *gin.Context) {
	var input TaskInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("user_id")
	task := models.Task{
		Title:        input.Title,
		Description:  input.Description,
		Points:       input.Points,
		Status:       "pending",
		CreatedByID:  userID,
		AssignedToID: input.AssignedToID,
	}

	if err := models.DB.Create(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create task"})
		return
	}

	// ✅ Create template if not already existing
	var existing models.TaskTemplate
	err := models.DB.Where("title = ? AND created_by_id = ?", input.Title, userID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		template := models.TaskTemplate{
			Title:       input.Title,
			Description: input.Description,
			Points:      input.Points,
			CreatedByID: userID,
		}
		models.DB.Create(&template)
	}

	c.JSON(http.StatusCreated, gin.H{"task": task})
}

func SubmitTask(c *gin.Context) {
	userID := c.GetUint("user_id")
	role := c.GetString("role")
	taskID := c.Param("id")

	var task models.Task
	if err := models.DB.First(&task, taskID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	if role != "child" || task.AssignedToID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized to submit this task"})
		return
	}

	task.Status = "awaiting_approval"
	models.DB.Save(&task)
	c.JSON(http.StatusOK, gin.H{"message": "task submitted for approval"})
}

func CompleteTask(c *gin.Context) {
	role := c.GetString("role")
	userID := c.GetUint("user_id")

	var task models.Task
	if err := models.DB.First(&task, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	// Allow child to submit task
	if role == "child" && task.AssignedToID == userID {
		task.Status = "awaiting_approval"
		models.DB.Save(&task)
		c.JSON(http.StatusOK, gin.H{"message": "task submitted for approval"})
		return
	}

	// Allow parent to approve task
	if role == "parent" {
		task.Status = "approved"

		// Add points to child
		var child models.User
		if err := models.DB.First(&child, task.AssignedToID).Error; err == nil {
			child.Points += task.Points
			models.DB.Save(&child)
		}

		models.DB.Save(&task)
		c.JSON(http.StatusOK, gin.H{"message": "task approved"})
		return
	}

	c.JSON(http.StatusForbidden, gin.H{"error": "not allowed"})
}

func ListTasks(c *gin.Context) {

	status := c.Query("status") // optional
	userID := c.GetUint("user_id")
	role := c.GetString("role")

	var tasks []models.Task
	if role == "parent" {
		query := models.DB.Where("created_by_id = ?", userID)

		if status != "" {
			if status == "pending" {
				// Include both pending and awaiting_approval
				query = query.Where("status IN ?", []string{"pending", "awaiting_approval"})
			} else {
				query = query.Where("status = ?", status)
			}
		}

		query.Find(&tasks)
	} else {
		query := models.DB.Where("assigned_to_id = ?", userID)
		if status != "" {
			query = query.Where("status = ?", status)
		}
		query.Find(&tasks)
	}

	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

func CreateReward(c *gin.Context) {
	userID := c.GetUint("user_id")
	log.Printf("CreateReward called by user ID: %d", userID)

	// If needed, check user from DB to verify role
	var user models.User
	if err := models.DB.First(&user, userID).Error; err != nil {
		log.Printf("User not found: %v", err)
		c.JSON(http.StatusForbidden, gin.H{"error": "user not found"})
		return
	}
	log.Printf("CreateReward: user role is %s", user.Role)

	if user.Role != "parent" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only parents can create rewards"})
		return
	}

	role := c.GetString("role")
	if role != "parent" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only parents can create rewards"})
		return
	}

	var input models.Reward
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	input.CreatedByID = c.GetUint("user_id")

	if err := models.DB.Create(&input).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create reward"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"reward": input})
}

func ListRewards(c *gin.Context) {
	var rewards []models.Reward
	role := c.GetString("role")
	userID := c.GetUint("user_id")

	if role == "parent" {
		models.DB.Where("created_by_id = ?", userID).Find(&rewards)
	} else {
		// Children can see all rewards created by their parent
		var child models.User
		if err := models.DB.First(&child, userID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		models.DB.Where("created_by_id = ?", child.ParentID).Find(&rewards)
	}

	c.JSON(http.StatusOK, gin.H{"rewards": rewards})
}

func RedeemReward(c *gin.Context) {
	role := c.GetString("role")
	if role != "child" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only children can redeem rewards"})
		return
	}

	childID := c.GetUint("user_id")
	rewardID := c.Param("id")

	var reward models.Reward
	if err := models.DB.First(&reward, rewardID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "reward not found"})
		return
	}

	var child models.User
	if err := models.DB.First(&child, childID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if child.Points < reward.Cost {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not enough points"})
		return
	}

	child.Points -= reward.Cost
	models.DB.Save(&child)

	redemption := models.Redemption{
		RewardID: reward.ID,
		ChildID:  child.ID,
		Status:   "requested",
	}

	models.DB.Create(&redemption)

	c.JSON(http.StatusOK, gin.H{"message": "reward redeemed", "redemption": redemption})
}

func ListRedemptions(c *gin.Context) {
	role := c.GetString("role")
	if role != "parent" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only parents can view redemptions"})
		return
	}

	parentID := c.GetUint("user_id")
	var children []models.User
	models.DB.Where("parent_id = ?", parentID).Find(&children)

	var childIDs []uint
	for _, c := range children {
		childIDs = append(childIDs, c.ID)
	}

	var redemptions []models.Redemption
	models.DB.Where("child_id IN ?", childIDs).Find(&redemptions)

	c.JSON(http.StatusOK, gin.H{"redemptions": redemptions})
}

func AssignBoilerplateTasks(c *gin.Context) {
	var input struct {
		TaskIDs []uint `json:"task_ids"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	userID := c.GetUint("user_id")

	for _, id := range input.TaskIDs {
		var template models.TaskTemplate
		if err := models.DB.First(&template, id).Error; err == nil {
			task := models.Task{
				Title:       template.Title,
				Description: template.Description,
				Points:      template.Points,
				Status:      "pending",
				CreatedByID: userID,
			}
			models.DB.Create(&task)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Boilerplate tasks assigned"})
}

func AssignBoilerplateRewards(c *gin.Context) {
	var input struct {
		RewardIDs []uint `json:"reward_ids"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	userID := c.GetUint("user_id")

	for _, id := range input.RewardIDs {
		var template models.RewardTemplate
		if err := models.DB.First(&template, id).Error; err == nil {
			reward := models.Reward{
				Title:       template.Title,
				Description: template.Description,
				Cost:        template.Cost,
				CreatedByID: userID,
			}
			models.DB.Create(&reward)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Boilerplate rewards assigned"})
}

func AddChildrenBulk(c *gin.Context) {
	var input struct {
		Children []models.User `json:"children"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	tokenString := c.GetHeader("Authorization")
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	claims, err := utils.ParseToken(tokenString) // or whatever your JWT parser is
	if err != nil {
		log.Println("failed to get token: ", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	parentID := claims.UserID
	log.Printf("Received children: %+v", input.Children)
	log.Printf("Assigning to parent ID: %d", parentID)

	for _, child := range input.Children {
		child.Role = "child"
		childParentID := parentID
		child.ParentID = &childParentID
		if child.Email == "" {
			child.Email = fmt.Sprintf("child_%d_%d@noemail.local", parentID, time.Now().UnixNano())
		}
		log.Printf("Received children: %+v", child)
		log.Printf("Assigning to parent ID: %d", parentID)

		if err := models.DB.Create(&child).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create one or more children"})
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Children created"})
}
