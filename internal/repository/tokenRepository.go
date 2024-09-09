package repository

import (
	"errors"
	"log"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// можно конечно сделать DBconnector интерфейсом
// tokenRepository тоже интерфейсом, с StoreToken GetToken методами
// было бы хорошо конечно уменьшить таким образом зависимость прямую, но оставил на потом да и забыл(
type TokenRepository struct {
	DB *DBconnector
}

func (repo *TokenRepository) StoreToken(token *RefreshToken) error {
	err := repo.validateToken(token)
	if err != nil {
		return err
	}

	err = repo.DB.Connection.Clauses(clause.OnConflict{
		UpdateAll: true, //на конфликте я обновляю данные в бд
	}).Create(&token).Error

	if err != nil {
		log.Printf("Ошибка при сохранении токена: %v", err)
		return err
	}
	return nil
}

func (repo *TokenRepository) GetToken(guid string) (*RefreshToken, error) {
	var refreshToken RefreshToken

	err := repo.DB.Connection.Where("user_guid = ?", guid).First(&refreshToken).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			log.Printf("Не удалось найти токен по запрошенному guid: %s", guid)
			return nil, err
		}
		log.Printf("Ошибка при получении токена: %v", err)
		return nil, err
	}
	return &refreshToken, nil
}

func (repo *TokenRepository) CreateTokenByArgs(guid, hashedRefreshToken, accessId string) (*RefreshToken, error) {
	//валидация данных, пока чт оне особо серьезная
	err := repo.validateRefreshTokenArgs(guid, hashedRefreshToken, accessId)
	if err != nil {
		return nil, err
	}

	return &RefreshToken{
		UserGUID:  guid,
		TokenHash: hashedRefreshToken,
		AccessID:  accessId,
	}, nil
}

func (repo *TokenRepository) validateToken(token *RefreshToken) error {
	return repo.validateRefreshTokenArgs(token.UserGUID, token.TokenHash, token.AccessID)
}

func (repo *TokenRepository) validateRefreshTokenArgs(guid, hashedRefreshToken, accessId string) error {
	if _, err := uuid.Parse(guid); err != nil {
		return errors.New("invalid GUID format")
	}
	if hashedRefreshToken == "" {
		return errors.New("hashed refresh token cannot be empty")
	}

	if accessId == "" {
		return errors.New("access ID cannot be empty")
	}

	return nil
}
