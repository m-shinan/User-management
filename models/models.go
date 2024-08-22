package models

type Users struct {
	Id         uint   `gorm:"primaryKey"`
	First_Name string `gorm:"not null"`
	Last_Name  string `gorm:"not null"`
	UserName   string `gorm:"unique;not null"`
	Email      string `gorm:"unique;not null"`
	Password   string `gorm:"not null"`
	Deleted    bool   `gorm:"default:false"`
}
