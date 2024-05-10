package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type someStruct struct {
	prop1 string
	prop2 string
}

func (cfg *ApiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
		someStruct := someStruct{}
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

func parseBody(s Parameters) Parameters {
	bannedWords := []string{"kerfuffle", "sharbert", "fornax"}

	parseBodyParams := Parameters{}
	parseBodyParams.Body = s.Body
	parseBodySplit := strings.Fields(parseBodyParams.Body)
	for i, words := range parseBodySplit {
		wordsToLower := strings.ToLower(words)
		for _, bannedWord := range bannedWords {
			if wordsToLower == bannedWord {
				parseBodySplit[i] = "****"
			}
		}
	}
	parseBodyParams.Body = strings.Join(parseBodySplit, " ")
	return parseBodyParams
}

func handlerPostChirps(w http.ResponseWriter, r *http.Request) {
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
	if len(params.Body) > 140 {
		errorResponse := ErrorResponse{Error: "Chirp is too long"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	parseParams := parseBody(params)
	id := 0
	validResponse := Chirp{
		Id:   id,
		Body: parseParams.Body,
	}
	id++
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(validResponse)

}

func main() {
	cfg := &ApiConfig{}
	const filepathRoot = "."
	const port = "8080"

	mux := http.NewServeMux()
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))
	mux.Handle("/app/", cfg.middlewareMetricsInc(fileServer))
	mux.HandleFunc("GET /api/healthz", handlerReadiness)
	mux.HandleFunc("GET /admin/metrics", cfg.handlerFileServerRequest)
	mux.HandleFunc("/api/reset", cfg.handlerFileServerRequestReset)
	mux.HandleFunc("POST /api/chirps", handlerPostChirps)
	mux.HandleFunc("GET /api/chirps", handlerGethirps)
	corsMux := middlewareCors(mux)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: corsMux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}
