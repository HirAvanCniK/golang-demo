package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"m0lecon.it/speedrun/auth"
)

type UserModel struct {
	gorm.Model
	Username string `gorm:"uniqueIndex"`
	Password string
	Role     string
}

func main() {
	secret := make([]byte, 32)
	rand.Read(secret)

	db, err := gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&UserModel{})

	r := gin.Default()

	r.POST("/register", func(c *gin.Context) {
		var register auth.RegisterRequest
		if err := c.ShouldBindJSON(&register); err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("ShouldBindJSON failed: %v", err))
		} else {
			user := UserModel{Username: register.Username, Password: register.Password, Role: "user"}
			if err := db.Create(&user).Error; err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("Create failed: %v", err))
			} else {
				c.JSON(http.StatusOK, auth.RegisterResponse{Success: true})
			}
		}
	})

	r.POST("/login", func(c *gin.Context) {
		var login auth.LoginRequest
		if err := c.ShouldBindJSON(&login); err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("ShouldBindJSON failed: %v", err))
		} else {
			var user UserModel
			if err := db.Where("username = ? AND password = ?", login.Username, login.Password).First(&user).Error; err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
			} else {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.Claims{Role: user.Role, StandardClaims: jwt.StandardClaims{
					ExpiresAt: 0,
					Issuer:    "auth",
					IssuedAt:  time.Now().Unix(),
				}})

				tokenString, err := token.SignedString([]byte(secret))
				if err != nil {
					c.String(http.StatusInternalServerError, fmt.Sprintf("SignedString failed: %v", err))
				} else {
					c.JSON(http.StatusOK, auth.LoginResponse{Token: tokenString})
				}
			}
		}
	})

	r.POST("/permissions", func(c *gin.Context) {
		var check auth.PermissionsRequest
		if err := c.ShouldBindJSON(&check); err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		parts := strings.Split(check.Token, ".")
		if len(parts) != 3 {
			c.String(http.StatusInternalServerError, "Token is not valid")
			return
		}

		var token jwt.Token

		// parse Header
		if headerBytes, err := jwt.DecodeSegment(parts[0]); err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("DecodeSegment head failed '%s': %v", parts[0], err))
		} else {
			if err := json.Unmarshal(headerBytes, &token.Header); err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("%s is not valid json: %v", headerBytes, err))
			}
		}

		// parse Claims
		if claimsBytes, err := jwt.DecodeSegment(parts[1]); err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("DecodeSegment middle failed '%s': %v", parts[1], err))
		} else {
			var claims auth.Claims
			if err := json.Unmarshal(claimsBytes, &claims); err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("%s is not valid json: %v", claimsBytes, err))
			}
			token.Claims = claims
		}

		// parse Method
		if alg, ok := token.Header["alg"].(string); !ok {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Header alg is not a string '%v'", token.Header["alg"]))
		} else if method := jwt.GetSigningMethod(alg); method == nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Header alg is not a signing method '%v'", token.Header["alg"]))
		} else {
			token.Method = method
			// validate
			payload := strings.Join(parts[0:2], ".")
			signature := parts[2]
			if err := token.Method.Verify(payload, signature, []byte(secret)); err == nil {
				token.Valid = true
			} else {
				c.String(http.StatusInternalServerError, fmt.Sprintf("Verify failed '%s': %v", payload, err))
			}
		}

		// check Claims
		if claims, ok := token.Claims.(auth.Claims); ok && token.Valid {
			c.JSON(http.StatusOK, auth.PermissionsResponse{Role: claims.Role})
		} else {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Claims are not valid %v", token.Claims))
		}
	})

	r.Run(":8081")
}
