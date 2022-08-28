package user_test

import (
	"config"
	"dbModel"
	"errors"
	"reflect"
	"testing"
	"time"
	"user"
)

/**
* init new user
 */
func initUser(tokenExpireTime time.Duration) *user.User {
	userModel, roleModel, userRoleModel, authTokenModel := dbModel.InitUser()
	userInfo := user.InitUser(userModel, roleModel, authTokenModel, userRoleModel, tokenExpireTime)
	return userInfo
}

/**
* test1 user create and delete
 */
func TestUserCase(t *testing.T) {
	user := initUser(config.TokenExpireTimeHour)
	// Create user
	err := user.CreateUser("user1", "pwd1")
	commonErrCheck(t, err, nil)
	err = user.CreateUser("user2", "pwd2")
	commonErrCheck(t, err, nil)
	// Create an existed user
	err = user.CreateUser("user1", "pwd3")
	commonErrCheck(t, err, config.ErrorUserExist)
	// Delete User
	err = user.DeleteUser("user1")
	commonErrCheck(t, err, nil)
	// Delete not existed user
	err = user.DeleteUser("user1")
	commonErrCheck(t, err, config.ErrorUserNotExist)
}

/**
* test2 role create and delete
 */
func TestRoleCase(t *testing.T) {
	user := initUser(config.TokenExpireTimeHour)
	// Create role
	err := user.CreateRole("role")
	commonErrCheck(t, err, nil)
	// Create an existed role
	err = user.CreateRole("role")
	commonErrCheck(t, err, config.ErrorRoleExist)
	// Delete role
	err = user.DeleteRole("role")
	commonErrCheck(t, err, nil)
	// Delete role not existed
	err = user.DeleteRole("role")
	commonErrCheck(t, err, config.ErrorRoleNotExist)
}

/**
* test3 token expire time
 */
func TestTokenExpireTime(t *testing.T) {
	user := initUser(config.TokenExpireTimeSec)

	// Create user
	err := user.CreateUser("user1", "pwd1")
	commonErrCheck(t, err, nil)

	// Right username and password.
	token, err := user.Authenticate("user1", "pwd1")
	commonErrCheck(t, err, nil)

	// No expired
	time.Sleep(time.Second * 1)
	_, err = user.CheckRole(token, "role")
	commonErrCheck(t, err, nil)
	_, err = user.AllRoles(token)
	commonErrCheck(t, err, nil)

	// has Expired
	time.Sleep(config.TokenExpireTimeSec)
	_, err = user.CheckRole(token, "role")
	commonErrCheck(t, err, config.ErrorTokenExpire)
	_, err = user.AllRoles(token)
	commonErrCheck(t, err, config.ErrorTokenExpire)
}

/**
* test4 token（Authenticate + Invalidate）
 */
func TestTokenCase(t *testing.T) {
	user := initUser(config.TokenExpireTimeHour)
	err := user.CreateUser("user1", "pwd1")
	// right username and right password.
	token, err := user.Authenticate("user1", "pwd1")
	commonErrCheck(t, err, nil)

	// add new role belong to user1
	err = user.CreateRole("role")
	commonErrCheck(t, err, nil)
	err = user.AddRoleToUser("user1", "role")
	commonErrCheck(t, err, nil)

	// Right username, wrong password.
	_, err = user.Authenticate("user1", "pwd2")
	commonErrCheck(t, err, config.ErrorPwd)

	// Wrong username.
	_, err = user.Authenticate("user3", "pwd1")
	commonErrCheck(t, err, config.ErrorUserNotExist)

	//check wrong token
	user.Invalidate("user10")

	// check all user role
	_, err = user.CheckRole(token, "role")
	commonErrCheck(t, err, nil)
	_, err = user.AllRoles(token)
	commonErrCheck(t, err, nil)

	// delete token and check all user role
	user.Invalidate(token)
	_, err = user.CheckRole(token, "role")
	commonErrCheck(t, err, config.ErrorToken)
	_, err = user.AllRoles(token)
	commonErrCheck(t, err, config.ErrorToken)
}

/**
* test5 test user with role
 */
func TestUserRole(t *testing.T) {
	user := initUser(config.TokenExpireTimeHour)
	err := user.CreateUser("user1", "pwd1")
	commonErrCheck(t, err, nil)
	token, err := user.Authenticate("user1", "pwd1")
	commonErrCheck(t, err, nil)

	// user1 has no roles.
	ok, err := user.CheckRole(token, "role")
	commonErrCheck(t, err, nil)
	deepErrCheck(t, ok, false)
	allRoles, err := user.AllRoles(token)
	commonErrCheck(t, err, nil)
	deepErrCheck(t, allRoles, []string(nil))

	// role not exist
	err = user.AddRoleToUser("user1", "role")
	commonErrCheck(t, err, config.ErrorRoleNotExist)

	// user not exist
	err = user.CreateRole("role")
	commonErrCheck(t, err, nil)
	err = user.AddRoleToUser("user9", "role")
	commonErrCheck(t, err, config.ErrorUserNotExist)

	// add role into user1
	err = user.AddRoleToUser("user1", "role")
	commonErrCheck(t, err, nil)
	ok, err = user.CheckRole(token, "role")
	commonErrCheck(t, err, nil)
	deepErrCheck(t, ok, true)
	allRoles, err = user.AllRoles(token)
	commonErrCheck(t, err, nil)
	deepErrCheck(t, allRoles, []string{"role"})

	// add role2
	err = user.CreateRole("role2")
	commonErrCheck(t, err, nil)
	err = user.AddRoleToUser("user1", "role2")
	ok, err = user.CheckRole(token, "role")
	commonErrCheck(t, err, nil)
	deepErrCheck(t, ok, true)
	ok, err = user.CheckRole(token, "role2")
	commonErrCheck(t, err, nil)
	deepErrCheck(t, ok, true)

	// role was deleted.
	err = user.DeleteRole("role")
	commonErrCheck(t, err, nil)
	ok, err = user.CheckRole(token, "role")
	commonErrCheck(t, err, nil)
	deepErrCheck(t, ok, false)
	allRoles, err = user.AllRoles(token)
	commonErrCheck(t, err, nil)
	deepErrCheck(t, allRoles, []string{"role2"})

	// user1 was deleted.
	err = user.DeleteUser("user1")
	commonErrCheck(t, err, nil)
	_, err = user.CheckRole(token, "role")
	commonErrCheck(t, err, config.ErrorToken)
	_, err = user.AllRoles(token)
	commonErrCheck(t, err, config.ErrorToken)

}

func commonErrCheck(t *testing.T, real, expect error) {
	if !errors.Is(expect, real) {
		t.Errorf("test: %s, expect: %v, real: %v", t.Name(), expect, real)
	}
}

func deepErrCheck(t *testing.T, real, expect interface{}) {
	if !reflect.DeepEqual(expect, real) {
		t.Errorf("test: %s, expect: %v, real: %v", t.Name(), expect, real)
	}
}
