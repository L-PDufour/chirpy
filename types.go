package main

import (
	"sync"
)

type ApiConfig struct {
	mutex          sync.Mutex
	fileserverHits int
}

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"cleaned_body"`
}
type ErrorResponse struct {
	Error string `json:"error"`
}
type Parameters struct {
	Body string `json:"body"`
}

type DB struct {
	path string
	mux  *sync.RWMutex
}
type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
}
