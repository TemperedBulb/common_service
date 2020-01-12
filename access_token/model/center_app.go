package model

import "github.com/jinzhu/gorm"

type CenterApp struct {
	gorm.Model
	AppName string `gorm:"type:varchar(255);unique_index"json:"app_name"`
	AppId   string `gorm:"type:varchar(255);unique_index"json:"app_id"`
	Secret  string `gorm:"type:varchar(255);unique_index"json:"secret"`
	Type    int8   `json:"type"`
}
