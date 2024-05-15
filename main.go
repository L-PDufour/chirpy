package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/L-PDufour/chirpy/internal/database"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
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

type PostLoginResponse struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Token string `json:"token"`
}

func (cfg *ApiConfig) handlerPostLogin(w http.ResponseWriter, r *http.Request) {
	fmt.Println("post login")
	type parameters struct {
		Password         string `json:"password"`
		Email            string `json:"email"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}
	type response struct {
		User
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	params := parameters{}
	if err := decoder.Decode(&params); err != nil {
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	if params.Email == "" || params.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	user, err := cfg.DB.GetUserByEmail(params.Email)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(params.Password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	defaultExpiration := 60 * 60 * 24
	if params.ExpiresInSeconds == 0 {
		params.ExpiresInSeconds = defaultExpiration
	} else if params.ExpiresInSeconds > defaultExpiration {
		params.ExpiresInSeconds = defaultExpiration
	}

	token, _ := cfg.Makejwt(time.Duration(params.ExpiresInSeconds)*time.Second, user.Id)
	responseData := PostLoginResponse{
		ID:    user.Id,
		Email: user.Email,
		Token: token,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseData)
}

func (cfg *ApiConfig) Makejwt(expiresInSeconds time.Duration, Id int) (string, error) {

	secretKey := []byte(cfg.jwtSecret)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Duration(expiresInSeconds))),
		Subject:   fmt.Sprintf("%d", Id),
	})
	return token.SignedString(secretKey)
}

func (cfg *ApiConfig) handlerPostUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("post user")
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	params := parameters{}
	if err := decoder.Decode(&params); err != nil {
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	if params.Email == "" || params.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	user, err := cfg.DB.CreateUser(params.Email, params.Password)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(jsonData)
	if err != nil {
		// Log the error but don't return it to the client
		fmt.Println("Error writing response:", err)
	}
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

type UpdateUserResponse struct {
	ID string `json:"id"`
}

func (cfg *ApiConfig) handlerPutUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("put user")
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type response struct {
		User
	}
	authHeader := r.Header.Get("Authorization")
	authFields := strings.Fields(authHeader)
	if len(authFields) != 2 || strings.ToLower(authFields[0]) != "bearer" {
		return
	}
	token := authFields[1]
	claimsStruct := jwt.RegisteredClaims{}
	tokenParsed, err := jwt.ParseWithClaims(
		token,
		&claimsStruct,
		func(token *jwt.Token) (interface{}, error) { return []byte(cfg.jwtSecret), nil })

	if err != nil {
		http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}
	fmt.Println("tokenParsed")
	userIdString, _ := tokenParsed.Claims.GetSubject()
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	params := parameters{}
	if err := decoder.Decode(&params); err != nil {
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}
	if params.Email == "" || params.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	fmt.Println("Password")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	fmt.Println("AfterPassword")
	fmt.Println("UpdateUser")
	userIdInt, err := strconv.Atoi(userIdString)
	user, _ := cfg.DB.UpdateUser(userIdInt, params.Email, string(hashedPassword))

	resp := response{User{
		Id:    user.Id,
		Email: user.Email,
	}}

	fmt.Println("Marshall")
	jsonResponse, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
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
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")

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
		DB:        db,
		jwtSecret: jwtSecret,
	}
	mux := http.NewServeMux()
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))
	mux.Handle("/app/", cfg.middlewareMetricsInc(fileServer))
	mux.HandleFunc("GET /api/healthz", handlerReadiness)
	mux.HandleFunc("GET /admin/metrics", cfg.handlerFileServerRequest)
	mux.HandleFunc("/api/reset", cfg.handlerFileServerRequestReset)
	mux.HandleFunc("POST /api/chirps", cfg.handlerPostChirps)
	mux.HandleFunc("POST /api/users", cfg.handlerPostUsers)
	mux.HandleFunc("PUT /api/users", cfg.handlerPutUsers)
	mux.HandleFunc("POST /api/login", cfg.handlerPostLogin)
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
