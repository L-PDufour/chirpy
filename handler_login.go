package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/L-PDufour/chirpy/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

func (cfg *ApiConfig) handlerPostLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password         string `json:"password"`
		Email            string `json:"email"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}
	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
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

	accessToken, err := auth.MakeJWT(
		user.Id,
		cfg.jwtSecret,
		time.Hour,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create access JWT")
		return
	}
	refreshToken, _ := auth.GenerateRefreshToken()
	err = cfg.DB.StoreRefreshToken(user.Id, refreshToken)

	respondWithJSON(w, http.StatusOK, response{
		User: User{
			Id:    user.Id,
			Email: user.Email,
		},
		Token:        accessToken,
		RefreshToken: refreshToken,
	})
}
