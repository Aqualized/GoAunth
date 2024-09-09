package aunth

import (
	"GoAunth/utils"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type ITokenCreator interface {
	CreateAccess(userGuid, clientIp, uniqueTokenId string) (string, error)
	CreateRefresh() (string, error)
	ParseToken(accessToken string) (*AccessClaims, error)
}

type TokenCreator struct {
	secretKey  string
	expMinutes int
}

type AccessClaims struct {
	jwt.StandardClaims
	UserGUID uuid.UUID  `json:"user_guid"`
	ClientIP netip.Addr `json:"client_ip"`
}

func NewTokenCreator(secretKey string, expInMinutes int) *TokenCreator {
	return &TokenCreator{
		secretKey:  secretKey,
		expMinutes: expInMinutes,
	}
}

func (creator *TokenCreator) CreateAccess(userGuid, clientIp, uniqueTokenId string) (string, error) {
	userId, err := uuid.Parse(userGuid)
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(clientIp)
	if err != nil {
		return "", err
	}
	claims := AccessClaims{
		jwt.StandardClaims{
			Id:        uniqueTokenId,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Duration(creator.expMinutes) * time.Minute).Unix(),
		},
		userId,
		ip,
	}
	unsignedToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := unsignedToken.SignedString([]byte(creator.secretKey))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (creator *TokenCreator) CreateRefresh() (string, error) {
	return utils.Generate_b64(32)
}

func (creator *TokenCreator) ParseToken(accessToken string) (*AccessClaims, error) {
	claims := &AccessClaims{}

	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{},
		error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("wrong signing method: %v", token.Header["alg"])
		}
		return []byte(creator.secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	resClaims, ok := token.Claims.(*AccessClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	return resClaims, nil
}
