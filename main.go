package main

import (
	"fmt" // TAMBAHKAN INI
	"log" // TAMBAHKAN INI
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	// "gorm.io/driver/sqlite" // HAPUS/KOMENTARI INI
	"gorm.io/driver/postgres" // TAMBAHKAN INI
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
	// Pastikan Anda mengatur JWT_SECRET di docker-compose.yaml
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
		// Konversi userID (uint) ke string dengan benar
		Subject:   fmt.Sprintf("%d", userID),
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)}

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
// ▼▼▼ FUNGSI INI DIUBAH TOTAL ▼▼▼
func setupDatabase() {
	// Baca variabel environment yang kita kirim dari docker-compose.yaml
	host := getEnv("DB_HOST", "localhost") // Akan menjadi "db"
	user := getEnv("DB_USER", "postgres")
	password := getEnv("DB_PASSWORD", "password_rahasia_anda")
	dbname := getEnv("DB_NAME", "english_learner_db")
	port := getEnv("DB_PORT", "5432")

	// Buat DSN (Data Source Name) untuk PostgreSQL
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Jakarta",
		host, user, password, dbname, port)

	var err error
	// Buka koneksi menggunakan driver Postgres
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Println("Gagal koneksi ke database. Info DSN:")
		log.Println(dsn) // Cetak DSN untuk debugging
		panic("Gagal koneksi ke database")
	}

	log.Println("Koneksi database berhasil!")
	db.AutoMigrate(&User{}, &Sentence{})
}
// ▲▲▲ FUNGSI INI DIUBAH TOTAL ▲▲▲


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

	// Endpoint health check sederhana
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP"})
	})

	// Jalan di port 5000 (sesuai kode Anda)
	r.Run(":5000")
}

// --- Handlers ---
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
	c.JSON(http.StatusOK, gin.H{"token": token})}

func handleAddSentence(c *gin.Context) {
	var input struct {
		Text string `json:"text" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Perbaikan: Ambil userID dari string
	userIDStr, _ := c.Get("userID")
	var userID uint
	fmt.Sscanf(userIDStr.(string), "%d", &userID) // Konversi string ke uint

	if userID == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memproses ID user"})
		return
	}
	sentence := Sentence{Text: input.Text, UserID: userID}
	db.Create(&sentence)
	c.JSON(http.StatusOK, gin.H{"message": "Kalimat berhasil ditambahkan", "data": sentence})
}

func handleGetRandomSentence(c *gin.Context) {
	// Perbaikan: Ambil userID dari string
	userIDStr, _ := c.Get("userID")
	var userID uint
	fmt.Sscanf(userIDStr.(string), "%d", &userID) // Konversi string ke uint

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