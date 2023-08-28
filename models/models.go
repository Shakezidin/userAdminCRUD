package models

type Users struct {
	Id         uint `gorm:"primary key"`
	UserName   string
	First_Name string
	Last_Name  string
	Email      string
	Password   string
}
