package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/L-PDufour/chirpy/internal/auth"
)

func (cfg *ApiConfig) handlerPostLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	decoder := json.NewDecoder(r.Body)

	params := parameters{}
	if err := decoder.Decode(&params); err != nil {
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	user, err := cfg.DB.GetUserByEmail(params.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get user")
		return
	}

	err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid password")
		return
	}

	accessToken, err := auth.MakeJWT(
		user.Id,
		cfg.jwtSecret,
		time.Hour,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create access JWT")
		return
	}
	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create refresh token")
		return
	}
	err = cfg.DB.StoreRefreshToken(user.Id, refreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't save refresh token")
		return
	}
	respondWithJSON(w, http.StatusOK, response{
		User: User{
			Id:    user.Id,
			Email: user.Email,
		},
		Token:        accessToken,
		RefreshToken: refreshToken,
	})
}
