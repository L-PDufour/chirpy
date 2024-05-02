package main

import "sync"

type apiConfig struct {
	mutex          sync.Mutex
	fileserverHits int
}

type ValidResponse struct {
	Cleaned_body string `json:"cleaned_body"`
}
type ErrorResponse struct {
	Error string `json:"error"`
}
type parameters struct {
	Body string `json:"body"`
}
