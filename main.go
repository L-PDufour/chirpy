package main

import (
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/L-PDufour/chirpy/internal/database"
)

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

func (cfg *ApiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func getCleanedBody(body string, bannedWords []string) string {
	words := strings.Split(body, " ")
	for i, word := range words {
		wordToLower := strings.ToLower(word)
		for _, bannedWord := range bannedWords {
			if wordToLower == bannedWord {
				words[i] = "****"
			}
		}
	}
	cleaned := strings.Join(words, " ")
	return cleaned
}

func validateChirp(body string) (string, error) {
	const maxChirpLenght = 140

	if len(body) > maxChirpLenght {
		return "", errors.New("Chirps is too long")
	}
	bannedWords := []string{"kerfuffle", "sharbert", "fornax"}
	cleaned := getCleanedBody(body, bannedWords)
	return cleaned, nil
}

func (cfg *ApiConfig) handlerPostChirps(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := Parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		errorResponse := ErrorResponse{Error: "Something went wrong"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(errorResponse)
		w.WriteHeader(500)
		return
	}
	cleaned, err := validateChirp(params.Body)
	if err != nil {
		errorResponse := ErrorResponse{Error: "Couldn't create chirp"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(errorResponse)
		w.WriteHeader(500)
		return
	}

	chirp, err := cfg.DB.CreateChirp(cleaned)
	w.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(Chirp{Id: chirp.Id, Body: chirp.Body})
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(201)
	w.Write(dat)
}

func (cfg *ApiConfig) handlerPostUsers(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	var params Parameters
	if err := decoder.Decode(&params); err != nil {
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	if params.Email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	user, err := cfg.DB.CreateUser(params.Email)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	responseData := User{
		Id:    user.Id,
		Email: user.Email,
	}

	jsonData, err := json.Marshal(responseData)
	if err != nil {
		http.Error(w, "Failed to marshal response data", http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonData)
}

func (cfg *ApiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := cfg.DB.GetChirps()
	if err != nil {
		return
	}

	chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, Chirp{
			Id:   dbChirp.Id,
			Body: dbChirp.Body,
		})
	}

	sort.Slice(chirps, func(i, j int) bool {
		return chirps[i].Id < chirps[j].Id
	})
	w.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(chirps)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

func (cfg *ApiConfig) handlerGetChirp(w http.ResponseWriter, r *http.Request) {
	idString := r.PathValue("id")
	idInt, err := strconv.Atoi(idString)
	dbChirp, err := cfg.DB.GetChirp(idInt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dbChirp)
}

func main() {
	debug := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *debug {
		err := os.Remove("database.json")
		if err != nil {
			log.Fatalf("Error deleting database: %v", err)
		}
		log.Println("Database deleted successfully")
		return
	}
	const filepathRoot = "."
	const port = "8080"
	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

	cfg := &ApiConfig{
		DB: db,
	}
	mux := http.NewServeMux()
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))
	mux.Handle("/app/", cfg.middlewareMetricsInc(fileServer))
	mux.HandleFunc("GET /api/healthz", handlerReadiness)
	mux.HandleFunc("GET /admin/metrics", cfg.handlerFileServerRequest)
	mux.HandleFunc("/api/reset", cfg.handlerFileServerRequestReset)
	mux.HandleFunc("POST /api/chirps", cfg.handlerPostChirps)
	mux.HandleFunc("POST /api/users", cfg.handlerPostUsers)
	mux.HandleFunc("GET /api/chirps", cfg.handlerGetChirps)
	mux.HandleFunc("GET /api/chirps/{id}", cfg.handlerGetChirp)
	corsMux := middlewareCors(mux)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: corsMux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}
