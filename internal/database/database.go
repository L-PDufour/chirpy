package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
	Id             int    `json:"id"`
	Email          string `json:"email"`
	HashedPassword string `json:"hashed_password"`
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Users  map[int]User  `json:"users"`
	Chirps map[int]Chirp `json:"chirps"`
}

func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mux:  &sync.RWMutex{},
	}
	if err := db.ensureDB(); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) CreateChirp(body string) (Chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	id := len(dbStructure.Chirps) + 1
	chirp := Chirp{
		Id:   id,
		Body: body,
	}
	dbStructure.Chirps[id] = chirp

	err = db.writeDB(dbStructure)
	if err != nil {
		return Chirp{}, err
	}

	return chirp, nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == email {
			return user, nil
		}
	}
	return User{}, fmt.Errorf("No user found with this email")
}
func (db *DB) GetUserById(userId int) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, ok := dbStructure.Users[userId]
	if !ok {
		return User{}, errors.New("User does not exist")
	}

	return user, nil
}

func (db *DB) UpdateUser(userId int, email, hashedPassword string) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, ok := dbStructure.Users[userId]
	if !ok {
		return User{}, errors.New("User does not exist")
	}

	user.Email = email
	user.HashedPassword = hashedPassword

	dbStructure.Users[userId] = user

	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (db *DB) CreateUser(email string, password string) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	id := len(dbStructure.Users) + 1
	for _, user := range dbStructure.Users {
		if email == user.Email {
			return User{}, err
		}
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user := User{
		Id:             id,
		Email:          email,
		HashedPassword: string(hashedPassword),
	}
	dbStructure.Users[id] = user

	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}

	return user, nil
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

func (db *DB) ensureDB() error {
	if _, err := os.Stat(db.path); os.IsNotExist(err) {
		emptyDB := DBStructure{
			Users:  make(map[int]User),
			Chirps: make(map[int]Chirp),
		}
		return db.writeDB(emptyDB)
	}
	return nil
}

func (db *DB) loadDB() (DBStructure, error) {
	file, err := os.Open(db.path)
	if err != nil {
		return DBStructure{}, err
	}
	defer file.Close()

	var dbStructure DBStructure
	if err := json.NewDecoder(file).Decode(&dbStructure); err != nil {
		return DBStructure{}, err
	}
	return dbStructure, nil
}

func (db *DB) writeDB(dbStructure DBStructure) error {
	file, err := os.Create(db.path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(dbStructure); err != nil {
		return err
	}
	return nil
}
