package aunth

import (
	"GoAunth/internal/repository"
	"GoAunth/utils"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenService struct {
	*repository.TokenRepository
	creator ITokenCreator
}

type TokenPair struct {
	AccessToken  string `json:"Access_token"`
	RefreshToken string `json:"Refresh_token"`
}

const (
	AuthorizationHeader = "Authorization"
	RefreshTokenHeader  = "Refresh-Token"
	BearerPrefix        = "Bearer "
)

func NewTokenService(repo *repository.TokenRepository, creator ITokenCreator) *TokenService {
	return &TokenService{
		TokenRepository: repo,
		creator:         creator,
	}
}

func (service *TokenService) CreateTokens(writer http.ResponseWriter, request *http.Request) {
	//берем параметры запр
	params := request.URL.Query()

	//смотрим guid
	guid := params.Get("guid")
	err := uuid.Validate(guid) //чекаем guid
	if err != nil {
		http.Error(writer, "wrong guid format", http.StatusBadRequest)
		return
	}

	//берем айпи пользователя
	ip, err := service.getIP(request)
	if err != nil {
		http.Error(writer, "ip was unobtainable "+err.Error(), http.StatusUnauthorized)
		return
	}

	//генерируем новый уник айди для аксесс токена
	accessId, err := service.generateUniqueId()
	if err != nil {
		http.Error(writer, "internal error generating accessId: "+err.Error(), http.StatusInternalServerError)
		return
	}

	//создаем новую пару токенов
	token_pair, err := service.createTokenPair(guid, ip, accessId)
	if err != nil {
		http.Error(writer, "error while creating tokens: "+err.Error(), http.StatusUnauthorized)
		return
	}

	//сохраняем новую пару токенчиков
	err = service.storetoken(guid, token_pair.RefreshToken, accessId)
	if err != nil {
		http.Error(writer, "error storing token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(token_pair)
}

func (service *TokenService) createTokenPair(guid, ip, accessId string) (*TokenPair, error) {
	accessToken, err := service.creator.CreateAccess(guid, ip, accessId)
	if err != nil {
		return nil, err
	}
	refreshToken, err := service.creator.CreateRefresh()
	if err != nil {
		return nil, err
	}

	token_pair := TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return &token_pair, nil
}

func (service *TokenService) storetoken(guid, refreshToken, accessId string) error {
	hashedToken, err := utils.HashRefresh(refreshToken)
	if err != nil {
		return err
	}
	refreshModel, err := service.CreateTokenByArgs(guid, hashedToken, accessId)
	if err != nil {
		return err
	}
	err = service.StoreToken(refreshModel)
	if err != nil {
		return err
	}
	return nil
}

func (service *TokenService) generateUniqueId() (string, error) {
	return utils.Generate_b64(16)
}

func (service *TokenService) RefreshTokens(writer http.ResponseWriter, request *http.Request) {
	//берем токены
	accessToken, refreshToken, err := service.getTokensFromRequest(request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	// берем claims из access токена
	claims, err := service.creator.ParseToken(accessToken)
	if err != nil {
		http.Error(writer, "invalid access token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// собираем все необходимые значения
	userGuid := claims.UserGUID.String()
	accesIp := claims.ClientIP.String()
	accessId, err := service.generateUniqueId() //генерим новое айди для новой пары токенов
	if err != nil {
		http.Error(writer, "inrernal error generating accessId: "+err.Error(), http.StatusInternalServerError)
		return
	}

	//берем модель что храница в бд
	tokenModel, err := service.GetToken(userGuid)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusUnauthorized)
		return
	}

	//берем айпи от запроса
	currentIp, err := service.getIP(request)
	if err != nil {
		http.Error(writer, "was not able to obtain Ip", http.StatusUnauthorized)
		return
	}
	//проверка изменения айпи адреса
	if accesIp != currentIp {
		service.fraudDetected()
		http.Error(writer, "ip changed, possible fraud", http.StatusUnauthorized)
		return
	}

	//чекаем если предоставленый рефреш токен ожидаемый
	if !service.validateRefreshToken(refreshToken, tokenModel.TokenHash) {
		http.Error(writer, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	//сравниваем связан ли предоставленный access token и refresh токен из бд
	if claims.Id != tokenModel.AccessID {
		http.Error(writer, "access ID of the token did not match with the stored one", http.StatusUnauthorized)
		return
	}

	//создаем новую пару токенов
	token_pair, err := service.createTokenPair(userGuid, currentIp, accessId)
	if err != nil {
		http.Error(writer, "error while creating tokens: "+err.Error(), http.StatusUnauthorized)
		return
	}
	//сохраняем новую пару токенчиков
	err = service.storetoken(userGuid, token_pair.RefreshToken, accessId)
	if err != nil {
		http.Error(writer, "error storing token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(token_pair)
}

func (service *TokenService) getTokensFromRequest(request *http.Request) (accessToken, refreshToken string, err error) {
	authHeader := request.Header.Get(AuthorizationHeader)
	if authHeader == "" {
		return "", "", service.logAndError("authorization header is missing")
	}
	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return "", "", service.logAndError("authorization header must start with 'Bearer '")
	}
	accessToken = strings.TrimPrefix(authHeader, BearerPrefix)

	refreshToken = request.Header.Get(RefreshTokenHeader)
	if refreshToken == "" {
		return "", "", service.logAndError("refresh-Token header is missing")
	}

	return accessToken, refreshToken, nil
}

// такое вот получение апихи, без углубления смотрел, а то там с X-Forward-For какие-то интересности могут быть
func (service *TokenService) getIP(req *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return "", err
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", err
	}

	return ip.String(), nil
}

func (service *TokenService) fraudDetected() {
	// якобы мейлим
	log.Println("mail => Ip changed, possible fraud.")
}

func (service *TokenService) logAndError(message string) error {
	log.Println(message)
	return errors.New(message)
}

// валидатор рефреш токена с хранимым хэшом в бд
func (service *TokenService) validateRefreshToken(refreshToken string, hashedToken string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken))
	if err != nil {
		log.Println(err.Error())
	}
	return err == nil
}
