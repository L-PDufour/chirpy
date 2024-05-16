package main

import (
	"net/http"
	"strconv"

	"github.com/L-PDufour/chirpy/internal/auth"
)

func (cfg *ApiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	idString := r.PathValue("id")
	idInt, err := strconv.Atoi(idString)

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
	dbChirp, err := cfg.DB.GetChirp(idInt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if dbChirp.AuthorId != userIDInt {
		respondWithError(w, http.StatusForbidden, "You don't have the permission")
	}
	err = cfg.DB.DeleteChirp(idInt)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to delete chirp")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
