package main

import (
	"github.com/L-PDufour/chirpy/internal/database"
	"sync"
)

type ApiConfig struct {
	mutex          sync.Mutex
	fileserverHits int
	DB             *database.DB
}

type ErrorResponse struct {
	Error string `json:"error"`
}
type Parameters struct {
	Body  string `json:"body"`
	Email string `json:"email"`
}
