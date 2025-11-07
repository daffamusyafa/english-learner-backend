package main

import (
	"errors" // <-- Ditambahkan untuk GORM
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv" // <-- Ditambahkan untuk .env
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- (Struct User & Sentence tidak berubah) ---
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

// --- (Variabel global & getEnv tidak berubah) ---
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

// --- (Fungsi hashPassword & checkPasswordHash tidak berubah) ---
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --- (Fungsi generateJWT & authMiddleware tidak berubah) ---
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

// --- (Fungsi setupDatabase tidak berubah) ---
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

// --- FUNGSI MAIN YANG SUDAH DIMODIFIKASI ---
func main() {
	// --- 1. Muat file .env di paling atas ---
	err := godotenv.Load()
	if err != nil {
		// Jangan panic jika file .env tidak ada (mungkin di produksi)
		log.Println("Peringatan: Tidak dapat memuat file .env. Menggunakan environment variable sistem.")
	}
	// -----------------------------------------

	setupDatabase()
	rand.Seed(time.Now().UnixNano()) // rand.Seed sudah deprecated di Go 1.20+, tapi tidak error
	r := gin.Default()

	// --- 2. Konfigurasi CORS dari .env ---
	config := cors.DefaultConfig()

	// Ambil FE URL dari .env, fallback ke localhost:8081
	feURL := getEnv("FRONTEND_URL", "http://localhost:8081")
	config.AllowOrigins = []string{feURL}

	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	config.AllowCredentials = true

	r.Use(cors.New(config))

	// --- Sisa router Anda (tidak berubah) ---
	r.POST("/register", handleRegister)
	r.POST("/login", handleLogin)

	api := r.Group("/api")
	api.Use(authMiddleware())
	{
		api.POST("/sentences", handleAddSentence)
		api.GET("/sentences/random", handleGetRandomSentence) // Menggunakan versi optimasi
	}

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP"})
	})

	// --- 3. Ambil Port dari .env ---
	appPort := getEnv("PORT", "5000")
	log.Printf("Server berjalan di port: %s", appPort)
	r.Run(":" + appPort)
}

// --- (handleRegister & handleLogin tidak berubah) ---

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
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// --- (handleAddSentence tidak berubah) ---

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

// --- FUNGSI handleGetRandomSentence VERSI OPTIMASI ---
func handleGetRandomSentence(c *gin.Context) {
	userIDStr, _ := c.Get("userID")
	var userID uint
	fmt.Sscanf(userIDStr.(string), "%d", &userID)
	if userID == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memproses ID user"})
		return
	}

	var sentence Sentence

	// Minta database (Postgres) untuk mengurutkan secara acak
	// dan hanya ambil 1 baris. Ini jauh lebih cepat.
	if err := db.Where("user_id = ?", userID).Order("RANDOM()").Limit(1).First(&sentence).Error; err != nil {

		// Cek apakah error-nya karena "tidak ada data"
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Anda belum menambahkan kalimat"})
			return
		}

		// Jika error lain (misal koneksi database putus)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil kalimat dari database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"id": sentence.ID, "text": sentence.Text})
}
