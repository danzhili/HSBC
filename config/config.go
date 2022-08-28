package config

import (
	"errors"
	"time"
)

var ErrorUserExist = errors.New("user is already exist")
var ErrorRoleExist = errors.New("role is already exist")
var ErrorToken = errors.New("token is wrong")
var ErrorUserNotExist = errors.New("user is not exist")
var ErrorRoleNotExist = errors.New("role is not exist")
var ErrorTokenExpire = errors.New("token is expired")
var ErrorPwd = errors.New("username or password is wrong")

var TokenExpireTimeHour = 1 * time.Hour
var TokenExpireTimeSec = 5 * time.Second
