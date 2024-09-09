package repository

type RefreshToken struct {
	UserGUID  string `gorm:"primaryKey;type:uuid"`
	TokenHash string `gorm:"type:text"`
	AccessID  string `gorm:"type:text"`
}
