package model

import (
	"github.com/jinzhu/gorm"
	"time"
)

type CenterAppToken struct {
	gorm.Model
	Expires     time.Time
	CenterAppId string `gorm:"type:varchar(255);unique_index"` // `type`设置sql类型, `unique_index` 为该列设置唯一索引
	AccessToken string `gorm:"type:varchar(255);"`
	Type        int64
}
