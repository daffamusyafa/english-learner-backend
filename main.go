package main

import (
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// --- Model Database ---

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

// --- Variabel Global ---
var (
	db     *gorm.DB
	jwtKey = []byte(getEnv("JWT_SECRET", "secret_sekali_jangan_ditiru"))
)

// --- Fungsi Helper ---

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
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.RegisteredClaims{
		Subject:   string(rune(userID)),
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// --- Middleware Otentikasi ---

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header dibutuhkan"})
			c.Abort()
			return
		}

		if len(tokenString) < 8 || tokenString[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Format token salah"})
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

// --- Setup Database ---
func setupDatabase() {
	var err error
	db, err = gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		panic("Gagal koneksi ke database")
	}
	db.AutoMigrate(&User{}, &Sentence{})
}

// --- Main Function ---
func main() {
	setupDatabase()
	rand.Seed(time.Now().UnixNano())

	r := gin.Default()
	
	// Tambahkan CORS middleware
	r.Use(func(c *gin.Context) {
        c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
        c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
        c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
        c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        c.Next()
    })

	// --- Public Routes ---
	r.POST("/register", handleRegister)
	r.POST("/login", handleLogin)

	// --- Private Routes (Butuh Auth) ---
	api := r.Group("/api")
	api.Use(authMiddleware())
	{
		api.POST("/sentences", handleAddSentence)
		api.GET("/sentences/random", handleGetRandomSentence)
	}

    // --- PERUBAHAN DI SINI ---
	r.Run(":5000") // Jalan di port 5000
}

// --- Handlers (Sama seperti sebelumnya) ---

func handleRegister(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hashedPassword, _ := hashPassword(input.Password)
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
	c.JSON(http.StatusOK, gin.H{"token": token})
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
	if id, ok := userIDStr.(string); ok {
		runes := []rune(id)
		if len(runes) > 0 {
			userID = uint(runes[0])
		}
	}
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
	if id, ok := userIDStr.(string); ok {
		runes := []rune(id)
		if len(runes) > 0 {
			userID = uint(runes[0])
		}
	}
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
