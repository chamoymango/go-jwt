package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"Message"`
}

var db *sql.DB

func main() {
	pgUrl, err := pq.ParseURL("postgres://jrhjgxqf:wcg_C1f7PYRY-dqqPUPGPUWtQWs3mlH3@salt.db.elephantsql.com:5432/jrhjgxqf")
	if err != nil {
		log.Fatal(err)
	}
	db, err = sql.Open("postgres", pgUrl)

	err = db.Ping()

	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVeriyMiddleware(protectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}
func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}
func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}
func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})
	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}
	return tokenString, nil
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		// respond with error
		error.Message = "Email is missing."
		// send status - bad request
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		// respond with error
		error.Message = "Password is missing."
		// bad request
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}
	user.Password = string(hash)

	stmt := "insert into users (email, password) values ($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		error.Message = "Server Error"
		respondWithError(w, http.StatusInternalServerError, error)
	}
	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)

}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	// var jwt JWT
	var error Error

	json.NewDecoder(r.Body).Decode(&user)

	spew.Dump(user)

	if user.Email == "" {
		error.Message = "Email is missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	password := user.Password

	row := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			respondWithError(w, http.StatusBadRequest, error)
			return
		} else {
			log.Fatal(err)
		}
	}

	hashedPassword := user.Password

	bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protected endpoint invoked")
	w.Write([]byte("Successfully called protected endpoint"))
}

func TokenVeriyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	fmt.Println("TokenMiddleware Invoked")
	return nil
}
