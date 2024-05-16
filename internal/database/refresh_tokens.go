package database

import (
	"time"
)

type RefreshToken struct {
	UserId    int       `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (db *DB) StoreRefreshToken(userId int, token string) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	refreshToken := RefreshToken{
		UserId:    userId,
		Token:     token,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	dbStructure.RefreshTokens[token] = refreshToken

	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) DeleteRefreshToken(token string) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}
	delete(dbStructure.RefreshTokens, token)
	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) GetUserByValidRefreshToken(token string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	refreshToken, ok := dbStructure.RefreshTokens[token]
	if !ok {
		return User{}, ErrNotExist
	}

	if refreshToken.ExpiresAt.Before(time.Now()) {
		return User{}, ErrNotExist
	}

	user, err := db.GetUserById(refreshToken.UserId)
	if err != nil {
		return User{}, err
	}

	return user, nil
}
