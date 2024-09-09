package main

import (
	"GoAunth/internal/aunth"
	"GoAunth/internal/repository"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

var rep *repository.TokenRepository
var port string
var secretkey string

func init() {
	var err error
	port = os.Getenv("PORT")
	secretkey = os.Getenv("SECRET_JWT_KEY")
	rep, err = repository.InitializeDefaultRepository()
	if err != nil {
		panic("Repository initialize failed: " + err.Error())
	}
}

func main() {
	router := mux.NewRouter()

	var expInMinutes = 5
	var tokenCreator aunth.ITokenCreator
	tokenCreator = aunth.NewTokenCreator(secretkey, expInMinutes)

	tokenService := aunth.NewTokenService(rep, tokenCreator)

	router.HandleFunc("/auth", tokenService.CreateTokens).Methods("POST")
	router.HandleFunc("/auth/refresh", tokenService.RefreshTokens).Methods("POST")

	log.Fatal(http.ListenAndServe(":"+port, router))
}

/*
func testCreateTokens() (string, string) {
	uuidValue := uuid.NewString() //генерирум guid для иммитации пользователя
	url := "http://localhost:" + os.Getenv("PORT") + "/auth?guid=" + uuidValue
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
		return "", ""
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
		return "", ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
		return "", ""
	}

	var tokenPair aunth.TokenPair
	err = json.Unmarshal(body, &tokenPair)
	if err != nil {
		log.Fatalf("Failed to unmarshal response body: %v", err)
	}

	log.Printf("--- TESTING _CreateTokens response: %s", body)
	return tokenPair.AccessToken, tokenPair.RefreshToken
}

func testRefreshTokens(accessToken, refreshToken string) {
	url := "http://localhost:" + os.Getenv("PORT") + "/auth/refresh"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Refresh-Token", refreshToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	log.Printf("--- TESTING _RefreshTokens response: %s", body)
}
*/
