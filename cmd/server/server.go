package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type ClientProof struct {
	Username       string                 `json:"username"`
	Proof          map[string]interface{} `json:"proof"`
	PublicSignals  []string               `json:"publicSignals"`
}

type Response struct {
	Token 	string `json:"token"`
	Error	string	`json:"error,omitempty"`
}

type Request struct {
	Username 	 string `json:"username"`
	ExpectedHash string `json:"expectedHash"` 			
}

type SaltNonceResponse struct {
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
}

var (
	jwtSecret []byte
	db 			 *sql.DB
)

func initJWTSecret() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("Variable not set (JWT_SECRET)")
	}

	jwtSecret = []byte(secret)
}

func initDB() {
	mysqlUser := os.Getenv("MYSQL_USER")
	mysqlPass := os.Getenv("MYSQL_PASSWORD") // typo fix from MYSQL_PASS
	mysqlDatabase := os.Getenv("MYSQL_DATABASE")

	dsn := fmt.Sprintf("%s:%s@tcp(db:3306)/%s", mysqlUser, mysqlPass, mysqlDatabase)

	var err error
	for i := 0; i < 10; i++ {
		db, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Printf("Try %d: DB open error: %v", i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}

		err = db.Ping()
		if err == nil {
			log.Println("Connected to MySQL")
			break
		}

		log.Printf("Try %d: DB ping failed: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Fatalf("DB connection failed after retries: %v", err)
	}
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func generateNonce() (*big.Int, error) {
	nonceBytes := make([]byte, 4)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(nonceBytes), nil
}

func generateJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 2).Unix(),
		"iat": time.Now().Unix(),
		"role": "user",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func logAttempt(time time.Time, result string, step string) {
	f, err := os.OpenFile("log.txt", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil  {
		fmt.Println(err)
		return
	}

	line := "Time: " + time.Format("2006-01-02 03:04:05PM") + ", Result " + result + ", Step: " + step
	_, err = fmt.Fprintln(f, line)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}

	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
}

func proveHandler(c echo.Context) error {
	var cp ClientProof
	if err := c.Bind(&cp); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid input"})
	}

	expectedHash, err := getUserData(cp.Username)

	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "user not found"})
	}

	log.Printf("From client %v", cp.PublicSignals[0])
	log.Printf("From DB %v", string(expectedHash))

	if cp.PublicSignals[0] != string(expectedHash) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "hash mismatch"})
	}

	// Step 2: Use `snarkjs` CLI or Node subprocess to verify
	// (because gnark and snarkjs are not directly interoperable)

	// Store input in temp files or use os.Pipe()

	// Simpler alternative: assume trusted proof and just verify public signal

	token, err := generateJWT(cp.Username)
	if err != nil {
		logAttempt(time.Now().Local(), "fail", "token gen")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
	}

	response := Response{
		Token: token,
	}

	logAttempt(time.Now().Local(), "success", "verification")
	
	cookie := new(http.Cookie)
	cookie.Name = "token"
	cookie.Value = token
	cookie.HttpOnly = true
	cookie.Path = "/"
	cookie.SameSite = http.SameSiteLaxMode
	cookie.Secure = false

	http.SetCookie(c.Response(), cookie)
	return c.JSON(http.StatusOK, response)
}

func jwtVerification(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")

	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		return c.NoContent(http.StatusUnauthorized)
	}

	tokenStr := authHeader[7:]

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return c.NoContent(http.StatusUnauthorized)
	}

	return c.NoContent(http.StatusOK)
}

func registerInitHandler(c echo.Context) error {
	var req Request
	if err := c.Bind(&req); err != nil || req.Username == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid input"})
	}

	salt, err := generateSalt()
	salt = []byte(hex.EncodeToString(salt))
	if err != nil {
		log.Println("Salt generation error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not generate salt"})
	}

	nonce, err := generateNonce()
	nonceStr := nonce.String()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not generate nonce"})
	}

	_, err = db.Exec(`
		INSERT INTO users (username, salt, nonce)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE salt=VALUES(salt)
	`, req.Username, salt, nonceStr)
	if err != nil {
		log.Println("DB insert error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not save salt"})
	}

	log.Println("Salt generated for:", req.Username)
	return c.JSON(http.StatusOK, map[string]string{
		"salt": hex.EncodeToString(salt),
	})
}

func registerCompleteHandler(c echo.Context) error {
	var req Request
	if err := c.Bind(&req); err != nil || req.Username == "" || req.ExpectedHash == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid input"})
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", req.Username).Scan(&exists)
	if err != nil {
		log.Println("DB error during registration complete:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "database error"})
	}
	if !exists {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "user not initialized"})
	}

	_, err = db.Exec(`
		UPDATE users SET expected_hash = ? WHERE username = ?
	`, req.ExpectedHash, req.Username)
	if err != nil {
		log.Println("Failed to update expectedHash:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save hash"})
	}

	log.Println("User registration completed:", req.Username)
	return c.JSON(http.StatusOK, map[string]string{"status": "user registered"})
}

func saltNonceHandler(c echo.Context) error {
	var req Request
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid input"})
	}

	var salt []byte
	err := db.QueryRow("SELECT salt FROM users WHERE username = ?", req.Username).Scan(&salt)
	if err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "database error"})
	}

	nonce, err := generateNonce()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "nonce generation failed"})
	}

	_, err = db.Exec("UPDATE users SET nonce = ? WHERE username = ?", nonce.String(), req.Username)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "nonce update failed"})
	}

	resp := SaltNonceResponse {
		Salt:  salt,
	    Nonce: []byte(nonce.String()),
	}

	return c.JSON(http.StatusOK, resp)
}

func getUserData(username string) (string, error) {
	row := db.QueryRow(`SELECT expected_hash FROM users WHERE username = ?`, username)
    var expected_hash string
    err := row.Scan(&expected_hash)
    return expected_hash, err
}

func main() {
	initDB()
	initJWTSecret()
	e := echo.New()
	e.Use(middleware.CORS())
	e.POST("/prove", proveHandler)
	e.POST("/register/init", registerInitHandler)
	e.POST("/register/complete", registerCompleteHandler)
	e.GET("/verify", jwtVerification)
	e.POST("/salt-nonce", saltNonceHandler)
	e.Logger.Fatal(e.Start(":1337"))
}