package auth

import "github.com/golang-jwt/jwt"

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterResponse struct {
	Success bool `json:"success"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type PermissionsRequest struct {
	Token string `json:"token" binding:"required"`
}

type PermissionsResponse struct {
	Role string `json:"role"`
}

type Claims struct {
	jwt.StandardClaims
	Role string `json:"role"`
}
