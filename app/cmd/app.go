package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"m0lecon.it/speedrun/auth"
)

func main() {
	authAddr, ok := os.LookupEnv("AUTH_ADDR")
	if !ok {
		panic("AUTH_ADDR not set")
	}

	flag, ok := os.LookupEnv("FLAG")
	if !ok {
		panic("FLAG not set")
	}

	r := gin.Default()

	r.POST("/register", func(c *gin.Context) {
		res, err := http.Post(fmt.Sprintf("http://%s/register", authAddr), "application/json", c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Register failed"})
			return
		}

		var registerRes auth.RegisterResponse
		err = json.NewDecoder(res.Body).Decode(&registerRes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Register failed"})
		} else {
			c.JSON(http.StatusOK, registerRes)
		}
	})

	r.POST("/login", func(c *gin.Context) {
		res, err := http.Post(fmt.Sprintf("http://%s/login", authAddr), "application/json", c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed"})
			return
		}

		var loginRes auth.LoginResponse
		err = json.NewDecoder(res.Body).Decode(&loginRes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed"})
		} else {
			c.JSON(http.StatusOK, loginRes)
		}
	})

	r.POST("/flag", func(c *gin.Context) {
		res, err := http.Post(fmt.Sprintf("http://%s/permissions", authAddr), "application/json", c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Flag failed"})
			return
		}

		var permissions auth.PermissionsResponse
		err = json.NewDecoder(res.Body).Decode(&permissions)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Flag failed"})
		} else if permissions.Role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		} else {
			c.JSON(http.StatusOK, gin.H{"flag": flag})
		}
	})

	r.Run(":8080")
}
