package database

import (
	"errors"
	"fmt"
)

type Chirp struct {
	AuthorId int    `json:"author_id"`
	Id       int    `json:"id"`
	Body     string `json:"body"`
}

func (db *DB) CreateChirp(body string, userId int) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	id := len(dbStructure.Chirps) + 1
	chirp := Chirp{
		AuthorId: userId,
		Id:       id,
		Body:     body,
	}
	fmt.Println(chirp)
	dbStructure.Chirps[id] = chirp

	err = db.writeDB(dbStructure)
	if err != nil {
		return Chirp{}, err
	}

	return chirp, nil
}

func (db *DB) GetChirps() ([]Chirp, error) {

	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	chirps := make([]Chirp, 0, len(dbStructure.Chirps))
	for _, chirp := range dbStructure.Chirps {
		chirps = append(chirps, chirp)
	}

	return chirps, nil
}

func (db *DB) DeleteChirp(chirpId int) error {

	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	if _, ok := dbStructure.Chirps[chirpId]; !ok {
		return errors.New("Chirp not found")
	}
	delete(dbStructure.Chirps, chirpId)
	return nil
}

func (db *DB) GetChirp(Id int) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	for _, chirp := range dbStructure.Chirps {
		if chirp.Id == Id {
			return chirp, nil
		}
	}
	return Chirp{}, fmt.Errorf("chirp with ID %d not found", Id)
}
