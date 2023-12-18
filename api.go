package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"log"

	"github.com/gorilla/mux"

	jwt "github.com/golang-jwt/jwt/v5"

	"os"
)

type APIServer struct {
	listenAddr string
	store storage
}

func permissionDenied(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, ApiError{Error: "permission denied"})
}

func withJWTAuth(handlerFunc http.HandlerFunc, s storage) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("calling JWT Auth middleware")
		

		tokenString := r.Header.Get("x-jwt-token")
		token, err := validateJWT(tokenString)

		if err != nil{
			permissionDenied(w)
			return
		}

		if !token.Valid {
			permissionDenied(w)
			return
		}

		// account, err := store.GetUserByJWTToken(token)
		// // err

		// claims := token.Claims.(jwt.MapClaims)

		// if claims["ID"] == account.ID

		// fmt.Println(claims)

		userID, err := getID(r)
		if err != nil{
			permissionDenied(w)
			return
		}
		
		account, err := s.GetAccountByID(userID)
		if err != nil{
			permissionDenied(w)
			return
		}

		claims := token.Claims.(jwt.MapClaims)

		if account.Number != int64(claims["accountNumber"].(float64)) {
			permissionDenied(w)
			return
		}

		if err != nil{
			writeJSON(w, http.StatusForbidden, ApiError{Error: "Invalid token"})
			return
		}

		handlerFunc(w, r)
	}
}


func validateJWT(tokenString string)(*jwt.Token, error) {
	secret := os.Getenv("JWT_SECRET")
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secret), nil
	})
}


type apiFunc func(http.ResponseWriter, *http.Request) error

type ApiError struct {
	Error string `json:"error"`
}


func writeJSON(w http.ResponseWriter, status int, v any) error{
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func createJWT(account *Account) (string, error) {
	// Create the Claims
	claims := &jwt.MapClaims{
		"ExpiresAt": 15000,
		"AccountNumber": account.Number,
	}

	secret := os.Getenv("JWT_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secret))
	//fmt.Println(ss, err)
}

// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBY2NvdW50TnVtYmVyIjo1MTE2NzcsIkV4cGlyZXNBdCI6MTUwMDB9.H60QmxfQGj343b279ZF1voCifucKjUYywCCmv5xX0fg


func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		if err := f(w, r); err != nil {
			// handle the error

			writeJSON(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

func newAPIServer(listenAddr string, store storage) *APIServer {

	return &APIServer{
		listenAddr: listenAddr,
		store: store,
	}
}

func (s *APIServer) Run(){
	router := mux.NewRouter()

	router.HandleFunc("/account", makeHTTPHandleFunc(s.handleAccount))

	router.HandleFunc("/account/{id}", withJWTAuth(makeHTTPHandleFunc(s.handleGetAccountByID), s.store))

	router.HandleFunc("/transfer", makeHTTPHandleFunc(s.handleTransfer))

	log.Println("JSON API server running on PORT: ", s.listenAddr)

	http.ListenAndServe(s.listenAddr, router)
}

func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error{
	if r.Method == "GET"{
		return s.handleGetAccount(w, r)
	}

	if r.Method == "POST"{
		return s.handleCreateAccount(w, r)
	}

	// if r.Method == "DELETE"{
	// 	return s.handleDeleteAccount(w, r)
	// }

	return fmt.Errorf("method not allowed %s", r.Method)
}

// Get /account/s
func (s *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error{
	accounts, err := s.store.GetAccounts()

	if err != nil{
		return err
	}

	return writeJSON(w, http.StatusOK, accounts)
}

func (s *APIServer) handleGetAccountByID(w http.ResponseWriter, r *http.Request) error{
	if r.Method == "GET"{
	id, err := getID(r)
	if err != nil{
		return err
	}

	account, err := s.store.GetAccountByID(id)

	if err != nil{
		return err
	}

	return writeJSON(w, http.StatusOK, account)
	}

	if r.Method == "DELETE"{
		return s.handleDeleteAccount(w, r)
	}

	return fmt.Errorf("method not allowed %s", r.Method)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error{
	createAccountReq := new(CreateAccountRequest)

	if err := json.NewDecoder(r.Body).Decode(createAccountReq); err != nil{
		return err
	}

	account := newAccount(createAccountReq.FirstName, createAccountReq.LastName)

	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

	tokenString, err := createJWT(account)

	if err != nil{
		return err
	}

	fmt.Println("JWT token: ", tokenString)

	return writeJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error{
	id, err := getID(r)
	if err != nil{
		return err
	}

	if err := s.store.DeleteAccount(id); err != nil{
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

func (s APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error{
	transferReq := new(TransferRequest)
	if err := json.NewDecoder(r.Body).Decode(transferReq); err != nil{
		return err
	}

	defer r.Body.Close()
	return writeJSON(w, http.StatusOK, transferReq)
}


func getID(r *http.Request) (int, error){
	idstr := mux.Vars(r)["id"]

	id, err := strconv.Atoi(idstr)

	if err != nil{
		return id, fmt.Errorf("invalid id given %s", idstr)
	}

	return id, nil
}