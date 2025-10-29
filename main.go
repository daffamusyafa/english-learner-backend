package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
}

type Sentence struct {
	ID     uint   `gorm:"primaryKey"`
	Text   string `gorm:"not null"`
	UserID uint   `gorm:"not null"`
	User   User   `gorm:"foreignKey:UserID"`
}

var (
	db     *gorm.DB
	jwtKey = []byte(getEnv("JWT_SECRET", "secret_sekali_jangan_ditiru"))
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateJWT(userID uint) (string, error) {
	exp := time.Now().Add(24 * time.Hour)
	claims := &jwt.RegisteredClaims{
		Subject:   fmt.Sprintf("%d", userID),
		ExpiresAt: jwt.NewNumericDate(exp),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" || len(tokenString) < 8 || tokenString[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Format token salah / token hilang"})
			c.Abort()
			return
		}
		tokenString = tokenString[7:]

		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid"})
			c.Abort()
			return
		}

		c.Set("userID", claims.Subject)
		c.Next()
	}
}

func setupDatabase() {
	host := getEnv("DB_HOST", "localhost")
	user := getEnv("DB_USER", "postgres")
	password := getEnv("DB_PASSWORD", "password_rahasia_anda")
	dbname := getEnv("DB_NAME", "english_learner_db")
	port := getEnv("DB_PORT", "5432")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Jakarta",
		host, user, password, dbname, port)

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Println("DSN:", dsn)
		panic("Gagal koneksi ke database")
	}

	log.Println("Database connected!")
	db.AutoMigrate(&User{}, &Sentence{})
}

func main() {
	setupDatabase()
	rand.Seed(time.Now().UnixNano())
	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	r.POST("/register", handleRegister)
	r.POST("/login", handleLogin)

	api := r.Group("/api")
	api.Use(authMiddleware())
	{
		api.POST("/sentences", handleAddSentence)
		api.GET("/sentences/random", handleGetRandomSentence)
	}

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP"})
	})

	r.Run(":5000")
}

func handleRegister(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hashedPassword, err := hashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal hashing password"})
		return
	}
	user := User{Username: input.Username, Password: hashedPassword}
	if result := db.Create(&user); result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username sudah ada"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Registrasi berhasil"})
}

func handleLogin(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var user User
	if result := db.Where("username = ?", input.Username).First(&user); result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Username atau password salah"})
		return
	}
	if !checkPasswordHash(input.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Username atau password salah"})
		return
	}
	token, err := generateJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": "Bearer " + token})
}

func handleAddSentence(c *gin.Context) {
	var input struct {
		Text string `json:"text" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userIDStr, _ := c.Get("userID")
	var userID uint
	fmt.Sscanf(userIDStr.(string), "%d", &userID)
	if userID == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memproses ID user"})
		return
	}
	sentence := Sentence{Text: input.Text, UserID: userID}
	db.Create(&sentence)
	c.JSON(http.StatusOK, gin.H{"message": "Kalimat berhasil ditambahkan", "data": sentence})
}

func handleGetRandomSentence(c *gin.Context) {
	userIDStr, _ := c.Get("userID")
	var userID uint
	fmt.Sscanf(userIDStr.(string), "%d", &userID)
	if userID == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memproses ID user"})
		return
	}
	var sentences []Sentence
	db.Where("user_id = ?", userID).Find(&sentences)
	if len(sentences) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Anda belum menambahkan kalimat"})
		return
	}
	randomSentence := sentences[rand.Intn(len(sentences))]
	c.JSON(http.StatusOK, gin.H{"id": randomSentence.ID, "text": randomSentence.Text})
}
