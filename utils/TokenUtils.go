package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

func GetIPAddress(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}

func Generate_b64(size int) (string, error) {
	idBytes := make([]byte, size)
	_, err := rand.Read(idBytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(idBytes), nil
}

func HashRefresh(refreshToken string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Failed to hash")
		return "", err
	}
	return string(hashedToken), nil
}

func ParseJWT(tokenString string, jwtkey []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("Unsupported signature method: %v", token.Header["alg"])
			return nil, fmt.Errorf("Unsupported signature method: %v", token.Header["alg"])
		}
		return jwtkey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

/*
func ExtractFromToken(tokenString, argument string, jwtkey []byte) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("Unsupported signature method: %v", token.Header["alg"])
			return nil, fmt.Errorf("Unsupported signature method: %v", token.Header["alg"])
		}
		return jwtkey, nil
	})

	if err != nil {
		log.Printf("Failed to parse given token: %v", err)
		return "", fmt.Errorf("Failed to parse given token: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		arg, ok := claims[argument].(string)
		if !ok {
			log.Printf("%s is absent in given token", argument)
			return "", fmt.Errorf("%s is absent in given token", argument)
		}
		return arg, nil
	}

	log.Printf("Wrong token")
	return "", fmt.Errorf("Wrong token")
}
*/
