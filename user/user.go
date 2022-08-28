package user

import (
	"config"
	"crypto/sha1"
	"dbModel"
	"encoding/hex"
	"math/rand"
	"strconv"
	"time"
)

type User struct {
	userModel       *dbModel.UserModel
	roleModel       *dbModel.RoleModel
	authTokenModel  *dbModel.AuthTokenModel
	userRoleModel   *dbModel.UserRoleModel
	tokenExpireTime int64
}

/**
* init user
 */
func InitUser(userModel *dbModel.UserModel, roleModel *dbModel.RoleModel, authTokenModel *dbModel.AuthTokenModel, userRoleModel *dbModel.UserRoleModel, tokenExpireTime time.Duration) *User {
	tokenExpireTimes := int64(tokenExpireTime) / int64(time.Second)
	res := &User{
		userModel:       userModel,
		roleModel:       roleModel,
		authTokenModel:  authTokenModel,
		userRoleModel:   userRoleModel,
		tokenExpireTime: tokenExpireTimes,
	}
	return res
}

/**
* add user
 */
func (u *User) CreateUser(userName string, passwd string) error {
	user := dbModel.User{
		UserName: userName,
		Pwd:      hash(passwd),
	}
	return u.userModel.AddUser(user)
}

/**
* delete user by name
 */
func (u *User) DeleteUser(userName string) error {
	u.userRoleModel.DeleteURUser(userName)
	u.authTokenModel.DeleteAuthTokenByName(userName)
	return u.userModel.DeleteUser(userName)
}

/**
* add role
 */
func (u *User) CreateRole(userName string) error {
	role := dbModel.Role{
		RoleName: userName,
	}
	return u.roleModel.AddRole(role)
}

/**
* delete role
 */
func (u *User) DeleteRole(roleName string) error {
	u.userRoleModel.DeleteURRole(roleName)
	return u.roleModel.DeleteRole(roleName)
}

/**
* add role to user
 */
func (u *User) AddRoleToUser(userName, roleName string) error {
	return u.userRoleModel.AddUserRole(userName, roleName)
}

/**
* Authenticate
 */
func (u *User) Authenticate(userName, passwd string) (string, error) {
	userInfo, OK := u.userModel.GetUser(userName)
	if !OK {
		return "", config.ErrorUserNotExist
	}
	if hash(passwd) != userInfo.Pwd {
		return "", config.ErrorPwd
	}
	timeNow := time.Now().Unix()
	token := hash(userName + strconv.FormatInt(timeNow+rand.Int63(), 10))
	authToken := dbModel.AuthToken{
		UserName:   userName,
		Token:      token,
		CreateTime: timeNow,
	}
	u.authTokenModel.AddAuthToken(authToken)
	return token, nil
}

/**
* Invalidate token
 */
func (u *User) Invalidate(token string) {
	u.authTokenModel.DeleteAuthTokenToken(token)
}

/**
* check role
 */
func (u *User) CheckRole(token, roleName string) (bool, error) {
	authToken, ok := u.authTokenModel.GetToken(token)
	if !ok {
		return false, config.ErrorToken
	}
	if time.Now().Unix()-authToken.CreateTime > u.tokenExpireTime {
		return false, config.ErrorTokenExpire
	}
	res := u.userRoleModel.CheckUserRoles(authToken.UserName, roleName)
	return res, nil
}

/**
* check role
 */
func (u *User) AllRoles(token string) ([]string, error) {
	authToken, ok := u.authTokenModel.GetToken(token)
	if !ok {
		return nil, config.ErrorToken
	}
	if time.Now().Unix()-authToken.CreateTime > u.tokenExpireTime {
		return nil, config.ErrorTokenExpire
	}
	res := u.userRoleModel.GetAllRolesByUserName(authToken.UserName)
	return res, nil
}

/**
* hash pwd
 */
func hash(input string) string {
	hash := sha1.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}

/**
* add user
 */
func (u *User) GetUser(userName string) (dbModel.User, bool) {
	return u.userModel.GetUser(userName)
}
