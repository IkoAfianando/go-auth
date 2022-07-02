package models

type User struct {
	// UserId serial primary_key
	UserId   int    `json:"user_id" gorm:"primary_key"`
	Address  string `json:"address"`
	Email    string `json:"email" gorm:"Unique"`
	Password []byte `json:"password"`
}
