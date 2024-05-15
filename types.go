package main

import (
	"github.com/L-PDufour/chirpy/internal/database"
	"sync"
)

type ApiConfig struct {
	mutex          sync.Mutex
	fileserverHits int
	DB             *database.DB
	jwtSecret      string
}

type ErrorResponse struct {
	Error string `json:"error"`
}
type Parameters struct {
	Body               string `json:"body"`
	Password           string `json:"password"`
	Email              string `json:"email"`
	Token              string `json:"token"`
	Expires_in_seconds int    `json:"expires_in_seconds"`
}
