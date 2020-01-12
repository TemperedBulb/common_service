package logic

import (
	"common_service/access_token/model"
	"common_service/access_token/protos"
	"common_service/common/i18n"
	"common_service/common/util"
	"context"
	"errors"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"time"
)

type AccessTokenLogic struct {
	Db                     *gorm.DB
	CenterApp              *model.CenterApp
	CenterAppTokenLogModel *model.CenterAppToken
}

func NewAccessTokenLogic(db *gorm.DB, centerAppModel *model.CenterApp, CenterAppTokenLogModel *model.CenterAppToken) *AccessTokenLogic {
	return &AccessTokenLogic{Db: db, CenterApp: centerAppModel, CenterAppTokenLogModel: CenterAppTokenLogModel}
}

type accessTokenCache struct {
	AppID   string    //应用id
	Expires time.Time //到期时间
}

var accessTokenList map[string]*accessTokenCache

func init() {
	accessTokenList = make(map[string]*accessTokenCache)
}

//GetAccessToken(context.Context, *GetAccessTokenRequest) (*AccessTokenResponse, error)
func (l *AccessTokenLogic) GetAccessToken(_ context.Context, r *protos.GetAccessTokenRequest) (*protos.AccessTokenResponse, error) {
	reply := new(protos.AccessTokenResponse)
	// 验证appID与secret
	l.Db.Where("app_id", r.AppId).First(&l.CenterApp)
	if l.CenterApp.AppId == "" {
		reply.Errmsg = "不存在此应用"
		return reply, nil
	}
	if l.CenterApp.Secret != r.Secret {
		reply.Errmsg = "app秘钥参数错误"
		return reply, nil
	}
	//删除缓存中的accessToken
	_ = unsetAccessTokenByAppID(r.AppId)
	// 根据appid和secret生成accesstoken
	encodeAesWord, expireTime := AesEncryptOfAccessToken(r.AppId, r.Secret)
	// 调用model层入库
	l.CenterAppTokenLogModel.CenterAppId = r.AppId
	l.CenterAppTokenLogModel.AccessToken = encodeAesWord
	l.CenterAppTokenLogModel.CreatedAt = time.Now()
	// 过期时间存为7500秒是为了防止应用有部分业务未处理完,延长5分钟过期(借鉴于微信)
	l.CenterAppTokenLogModel.Expires = time.Now().Add((7500) * time.Second)
	l.Db.Create(&l.CenterAppTokenLogModel)
	// 设置accessToken到缓存

	reply.AccessToken = encodeAesWord
	reply.Expires = expireTime.String()
	return reply, nil
}

// 检测AccessToken
func (l *AccessTokenLogic) CheckAccessToken(_ context.Context, r *protos.CheckAccessTokenRequest) (*protos.CheckAccessTokenResponse, error) {
	reply := new(protos.CheckAccessTokenResponse)
	err := CheckAccessTokenByToken(r.AppId, r.AccessToken)
	if err != nil {
		reply.ResultCode = i18n.AccessTokenIsFailErrorMsg
		reply.ResultMsg = err.Error()
		return reply, nil
	}
	reply.ResultCode = i18n.SuccessCode
	reply.ResultMsg = i18n.Success
	return reply, nil
}

//验证access_token(使用缓存处理)
func CheckAccessTokenByToken(appID string, accessToken string) error {
	cacheAppId, _, err := GetAccessToken(accessToken)
	if err != nil {
		return err
	}
	if cacheAppId != appID {
		return errors.New("access_token 无效")
	}
	return nil
}

// 刷新accessToken
//	FlushAccessToken(context.Context, *FlushAccessTokenRequest) (*AccessTokenResponse, error)
func (l *AccessTokenLogic) FlushAccessToken(_ context.Context, r *protos.FlushAccessTokenRequest) (*protos.AccessTokenResponse, error) {
	reply := new(protos.AccessTokenResponse)
	if nil == accessTokenList[r.AccessToken] {
		reply.Errcode = 400001
		return reply, errors.New(i18n.AccessTokenNotFlushErrorMsg)
	}
	accessTokenList[r.AccessToken].Expires = time.Time{}.Add(time.Duration(7200 * int64(time.Second)))
	reply.AccessToken = r.AccessToken
	reply.Expires = accessTokenList[r.AccessToken].Expires.String()
	return reply, nil
}

//设置access_token
func SetAccessToken(accessToken string, appId string, expires time.Time) error {
	if nil != accessTokenList[accessToken] {
		return errors.New("access_token 不可被重复设置")
	}
	_ = unsetAccessTokenByAppID(appId)
	accessTokenList[accessToken] = &accessTokenCache{AppID: appId, Expires: expires}
	return nil
}

//清理过期无效access_token减少内存开销
func cleanRunner() {
	logrus.Println("开始清理access_token")
	for at := range accessTokenList {
		_ = CheckAccessToken(at)
	}
}

//通过appId清理缓存
func unsetAccessTokenByAppID(appID string) error {
	for at, ats := range accessTokenList {
		if ats.AppID == appID {
			delete(accessTokenList, at)
			return nil
		}
	}
	logrus.Info("未找到对应AccessToken")
	return errors.New("未找到对应AccessToken")
}

//获取access_token
func GetAccessToken(accessToken string) (appId string, expires time.Time, err error) {
	if nil == accessTokenList[accessToken] {
		return appId, expires, errors.New("access_token 不存在")
	}
	//验证是否过期
	err = CheckAccessToken(accessToken)
	if err != nil {
		return appId, expires, err
	}
	appId = accessTokenList[accessToken].AppID
	expires = accessTokenList[accessToken].Expires
	return appId, expires, nil
}

//验证过期
func CheckAccessToken(accessToken string) error {
	if nil == accessTokenList[accessToken] {
		return errors.New("无效 access_token")
	}
	//当前时间大于过期时间，清空
	if time.Now().UnixNano() > accessTokenList[accessToken].Expires.UnixNano() {
		delete(accessTokenList, accessToken)
		return errors.New("access_token 已经过期")
	}
	return nil
}

// 加密appId和secret获取AccessToken
func AesEncryptOfAccessToken(appId, secret string) (encodeAesWordStr string, expireTime time.Time) {
	origData := []byte(appId)
	key := []byte(secret)
	encodeAesWord := util.AESEncrypt(origData, key)
	expireTime = time.Time{}.Add(time.Duration(7200 * int64(time.Second)))
	accessTokenList[string(encodeAesWord)] = &accessTokenCache{
		AppID:   appId,
		Expires: expireTime,
	}
	return string(encodeAesWord), expireTime
}
