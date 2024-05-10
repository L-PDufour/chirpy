package main

import (
	"sync"

	"github.com/L-PDufour/chirpy/internal/database"
)

type ApiConfig struct {
	mutex          sync.Mutex
	fileserverHits int
	DB             *database.DB
}

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}
type ErrorResponse struct {
	Error string `json:"error"`
}
type Parameters struct {
	Body string `json:"body"`
}
