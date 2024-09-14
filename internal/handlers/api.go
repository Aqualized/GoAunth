package handlers

import (
	"GoAunth/internal/aunth"
	"GoAunth/internal/repository"
	"os"

	"github.com/gorilla/mux"
)

var rep *repository.TokenRepository
var secretkey string
var tokenCreator aunth.ITokenCreator
var expInMinutes = 5

func init() {
	secretkey = os.Getenv("SECRET_JWT_KEY")

	var err error //инициализация бд для токенов
	rep, err = repository.InitializeDefaultRepository()
	if err != nil {
		panic("Repository initialize failed: " + err.Error())
	}
}

func Handler(r *mux.Router) {
	tokenCreator = aunth.NewTokenCreator(secretkey, expInMinutes)
	tokenService := aunth.NewTokenService(rep, tokenCreator)

	r.HandleFunc("GET /auth", tokenService.CreateTokens)
	r.HandleFunc("POST /auth/refresh", tokenService.RefreshTokens)
}
