package repository

import (
	"fmt"
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// разделил на две сущности подключение к Бд и работа уже с подключенной бд - токен репа
type DBconnector struct {
	Connection *gorm.DB
}

func (db *DBconnector) Connect(dbHost, dbPort, dbUser, dbPassword, dbName string) error {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	//были issues с подключением к дб на моем ноуте почему то только в один день
	//на следующий день пропали проблемы, но решил все равно добавить множественные попытки подключиться
	var err error
	var maxRetries = 10
	var delay = 2 * time.Second

	for i := 0; i < maxRetries; i++ {
		db.Connection, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err == nil {
			break
		}
		if i < maxRetries-1 {
			log.Printf("Failed to connect to DB, retrying in %v: %v", delay, err)
			time.Sleep(delay)
		}
	}

	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
		return err
	}

	err = db.Connection.AutoMigrate(&RefreshToken{})
	if err != nil {
		log.Fatalf("Migration error: %v", err)
		return err
	}

	log.Println("Table was created or existed")
	return nil
}
