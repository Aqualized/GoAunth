package repository

import (
	"os"
)

func InitializeDefaultRepository() (*TokenRepository, error) {
	//для примерчика берем из окружения
	db_Host := os.Getenv("DB_HOST")
	db_Port := os.Getenv("DB_PORT")
	db_User := os.Getenv("DB_USER")
	db_Password := os.Getenv("DB_PASSWORD")
	db_Name := os.Getenv("DB_NAME")
	//создадим сущность коннектора вначале
	db := &DBconnector{}
	//попробуем ка подключиться к бд
	err := db.Connect(db_Host, db_Port, db_User, db_Password, db_Name)
	if err != nil {
		return nil, err
	}

	//если все ок делаем репу
	tokenRepo := &TokenRepository{DB: db}
	return tokenRepo, nil
}
