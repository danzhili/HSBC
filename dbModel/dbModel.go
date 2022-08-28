package dbModel

import "config"

type User struct {
	UserName string
	Pwd      string
}

type Role struct {
	RoleName string
}

type AuthToken struct {
	UserName   string
	Token      string
	CreateTime int64
}

type UserModel struct {
	UserData map[string]User
}

type RoleModel struct {
	RoleData map[string]Role
}

type UserRoleModel struct {
	UserModel *UserModel
	RoleModel *RoleModel
	UserRole  map[string]map[string]struct{}
}

type AuthTokenModel struct {
	UserModel *UserModel
	Token     map[string]AuthToken
	Name      map[string]AuthToken
}

func InitUser() (*UserModel, *RoleModel, *UserRoleModel, *AuthTokenModel) {
	newUser := &UserModel{UserData: make(map[string]User)}
	newRole := &RoleModel{RoleData: make(map[string]Role)}
	newUserRole := &UserRoleModel{
		UserModel: newUser,
		RoleModel: newRole,
		UserRole:  make(map[string]map[string]struct{}),
	}
	newAuthToken := &AuthTokenModel{
		UserModel: newUser,
		Token:     make(map[string]AuthToken),
	}
	return newUser, newRole, newUserRole, newAuthToken
}

/**
* get user info by username
 */
func (user *UserModel) GetUser(name string) (User, bool) {
	userInfo, OK := user.UserData[name]
	return userInfo, OK
}

/**
* get role info by rolename
 */
func (role *RoleModel) GetRole(name string) (Role, bool) {
	roleInfo, OK := role.RoleData[name]
	return roleInfo, OK
}

/**
* get authToken by token
 */
func (t *AuthTokenModel) GetTokenGetToken(token string) (AuthToken, bool) {
	userToken, OK := t.Token[token]
	return userToken, OK
}

/**
* check user role is exist
 */
func (ur *UserRoleModel) CheckUserRoles(userName string, roleName string) bool {
	_, OK := ur.UserRole[userName][roleName]
	return OK
}

/**
* get authToken by token
 */
func (ur *UserRoleModel) GetAllRolesByUserName(userName string) []string {
	var res []string
	for role := range ur.UserRole[userName] {
		res = append(res, role)
	}
	return res
}

/**
* add new user
 */
func (user *UserModel) AddUser(newUser User) error {
	if _, OK := user.UserData[newUser.UserName]; OK {
		return config.ErrorUserExist
	}
	user.UserData[newUser.UserName] = newUser
	return nil
}

/**
* add new role
 */
func (role *RoleModel) AddRole(newRole Role) error {
	if _, OK := role.RoleData[newRole.RoleName]; OK {
		return config.ErrorRoleExist
	}
	role.RoleData[newRole.RoleName] = newRole
	return nil
}

/**
* add new authToken
 */
func (authToken *AuthTokenModel) AddAuthToken(newAuthToken AuthToken) error {
	if _, OK := authToken.UserModel.GetUser(newAuthToken.UserName); OK {
		return config.ErrorToken
	}
	authToken.Token[newAuthToken.Token] = newAuthToken
	authToken.Name[newAuthToken.UserName] = newAuthToken
	return nil
}

/**
* add new userRole
 */
func (ur *UserRoleModel) AddUserRole(userName string, roleName string) error {
	if _, OK := ur.UserModel.GetUser(userName); OK {
		return config.ErrorUserNotExist
	}
	if _, OK := ur.RoleModel.GetRole(roleName); OK {
		return config.ErrorRoleNotExist
	}
	ur.UserRole[userName][roleName] = struct{}{}
	return nil
}

/**
* delete user by username
 */
func (user *UserModel) DeleteUser(userName string) error {
	if _, OK := user.UserData[userName]; !OK {
		return config.ErrorUserNotExist
	}
	delete(user.UserData, userName)
	return nil
}

/**
* delete role by roleName
 */
func (role *RoleModel) DeleteRole(roleName string) error {
	if _, OK := role.RoleData[roleName]; !OK {
		return config.ErrorRoleNotExist
	}
	delete(role.RoleData, roleName)
	return nil
}

/**
* delete authToken by name
 */
func (authToken *AuthTokenModel) DeleteAuthTokenByName(name string) error {
	authInfoToken, OK := authToken.Name[name]
	if !OK {
		return config.ErrorToken
	}
	delete(authToken.Name, name)
	delete(authToken.Token, authInfoToken.Token)
	return nil
}

/**
* delete authToken by Token
 */
func (authToken *AuthTokenModel) DeleteAuthTokenToken(token string) error {
	authInfoToken, OK := authToken.Token[token]
	if !OK {
		return config.ErrorToken
	}
	delete(authToken.Name, authInfoToken.UserName)
	delete(authToken.Token, token)
	return nil
}

/**
* delete user role by user
 */
func (ur *UserRoleModel) DeleteURUser(name string) {
	delete(ur.UserRole, name)
}

/**
* delete user role by role
 */
func (ur *UserRoleModel) DeleteURRole(name string) {
	for _, roles := range ur.UserRole {
		delete(roles, name)
	}
}
