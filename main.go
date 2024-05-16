package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/L-PDufour/chirpy/internal/database"
	"github.com/joho/godotenv"
)

type ApiConfig struct {
	fileserverHits int
	DB             *database.DB
	jwtSecret      string
}

func main() {

	const filepathRoot = "."
	const port = "8080"

	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}
	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

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

	cfg := &ApiConfig{
		fileserverHits: 0,
		DB:             db,
		jwtSecret:      jwtSecret,
	}

	mux := http.NewServeMux()
	fsHandler := cfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot))))
	mux.Handle("/app/*", fsHandler)

	mux.HandleFunc("GET /api/healthz", handlerReadiness)
	mux.HandleFunc("GET /api/reset", cfg.handlerReset)

	mux.HandleFunc("POST /api/chirps", cfg.handlerPostChirps)
	mux.HandleFunc("GET /api/chirps", cfg.handlerGetChirps)
	mux.HandleFunc("GET /api/chirps/{id}", cfg.handlerGetChirp)

	mux.HandleFunc("POST /api/users", cfg.handlerPostUsers)
	mux.HandleFunc("PUT /api/users", cfg.handlerPutUsers)

	mux.HandleFunc("POST /api/login", cfg.handlerPostLogin)
	mux.HandleFunc("POST /api/refresh", cfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", cfg.handlerRevoke)

	mux.HandleFunc("GET /admin/metrics", cfg.handlerMetrics)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}
