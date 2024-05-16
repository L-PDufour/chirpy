package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/L-PDufour/chirpy/internal/auth"
)

type Chirp struct {
	AuthorId int    `json:"author_id"`
	Id       int    `json:"id"`
	Body     string `json:"body"`
}

func (cfg *ApiConfig) handlerPostChirps(w http.ResponseWriter, r *http.Request) {

	type parameters struct {
		Body string `json:"body"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}
	subject, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't validate JWT")
		return
	}

	userIDInt, err := strconv.Atoi(subject)
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	cleaned, err := validateChirp(params.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	chirp, err := cfg.DB.CreateChirp(cleaned, userIDInt)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create chirp")
		return
	}
	respondWithJSON(w, http.StatusCreated, Chirp{
		Id:       chirp.Id,
		AuthorId: userIDInt,
		Body:     chirp.Body,
	})

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
