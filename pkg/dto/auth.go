package dto

// RegisterReq is the body of POST /api/v1/auth/register.
type RegisterReq struct {
	Username string `json:"username" validate:"required,min=3,max=64"`
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required"`
	Nickname string `json:"nickname" validate:"omitempty,max=255"`
}

// LoginReq is the body of POST /api/v1/auth/login (identifier = username or
// email, lower-normalized).
type LoginReq struct {
	Identifier string `json:"identifier" validate:"required,max=255"`
	Password   string `json:"password" validate:"required"`
}

// AccountLoginReq is the body of POST /api/v1/auth/account-login (direct
// workspace sign-in).
type AccountLoginReq struct {
	App        string `json:"app" validate:"required,max=64"`
	Identifier string `json:"identifier" validate:"required,max=255"`
	Password   string `json:"password" validate:"required"`
}

// SendEmailCodeReq is the body of POST /api/v1/auth/email/code.
type SendEmailCodeReq struct {
	Email   string `json:"email" validate:"required,email,max=255"`
	Purpose string `json:"purpose" validate:"required,oneof=login register reset"`
}

// EmailLoginReq is the body of POST /api/v1/auth/email/login.
type EmailLoginReq struct {
	Email string `json:"email" validate:"required,email,max=255"`
	Code  string `json:"code" validate:"required,len=6"`
}

// PasswordSetReq is the body of POST /api/v1/auth/password/set (first-time
// password for auto-provisioned identities).
type PasswordSetReq struct {
	Email       string `json:"email" validate:"required,email,max=255"`
	Code        string `json:"code" validate:"required"`
	NewPassword string `json:"new_password" validate:"required"`
}

// PasswordResetReq is the body of POST /api/v1/auth/password/reset.
type PasswordResetReq struct {
	Email       string `json:"email" validate:"required,email,max=255"`
	Code        string `json:"code" validate:"required"`
	NewPassword string `json:"new_password" validate:"required"`
}

// AccountActivateReq is the body of POST /api/v1/auth/accounts/activate
// (activation of a provisioned pending_activation workspace account).
type AccountActivateReq struct {
	App         string `json:"app" validate:"required,max=64"`
	Email       string `json:"email" validate:"required,email,max=255"`
	Code        string `json:"code" validate:"required"`
	NewPassword string `json:"new_password" validate:"required"`
}

// RefreshReq is the body of POST /api/v1/auth/token/refresh.
type RefreshReq struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// LogoutReq is the optional body of POST /api/v1/auth/logout.
type LogoutReq struct {
	RefreshToken string `json:"refresh_token"`
}

// SessionInfo describes the session backing a freshly issued token pair.
type SessionInfo struct {
	ID     string `json:"id"`
	Device string `json:"device"`
	IP     string `json:"ip"`
}

// TokenPair is the standard token response payload.
type TokenPair struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int64        `json:"expires_in"`
	Session      *SessionInfo `json:"session,omitempty"`
}

// LoginResp is the response of the identity login endpoints. When the
// identity has 2FA enabled the response carries only mfa_required+mfa_token
// (no tokens are issued until POST /api/v1/auth/login/2fa succeeds).
type LoginResp struct {
	AccessToken  string       `json:"access_token,omitempty"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	TokenType    string       `json:"token_type,omitempty"`
	ExpiresIn    int64        `json:"expires_in,omitempty"`
	Session      *SessionInfo `json:"session,omitempty"`
	MfaRequired  bool         `json:"mfa_required,omitempty"`
	MfaToken     string       `json:"mfa_token,omitempty"`
}

// Login2FAReq is the body of POST /api/v1/auth/login/2fa. Code accepts a
// 6-digit TOTP code or a backup code (dashes optional).
type Login2FAReq struct {
	MfaToken string `json:"mfa_token" validate:"required"`
	Code     string `json:"code" validate:"required,max=16"`
}

// RegisterResp is the response of POST /api/v1/auth/register (201).
type RegisterResp struct {
	TokenPair
	Me *Me `json:"me"`
}

// AccountTokenResp is the response of workspace token issuance (account-login
// and POST /me/workspaces/{id}/token).
type AccountTokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	AccountID    string `json:"account_id"`
	AppKey       string `json:"app_key"`
}

// AccountActivateResp is the response of POST /api/v1/auth/accounts/activate.
type AccountActivateResp struct {
	AccountID string `json:"account_id"`
	AppKey    string `json:"app_key"`
	Status    string `json:"status"`
}
