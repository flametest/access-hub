package dto

import "time"

// SocialCompleteReq is the body of POST /api/v1/auth/social/complete: the
// one-time login_code handed out by the social callback redirect (tokens
// never travel through URLs).
type SocialCompleteReq struct {
	LoginCode string `json:"login_code" validate:"required,max=128"`
}

// PendingInvitation is one "We found N workspaces" entry: an unaccepted,
// unexpired invitation waiting for the signing-in identity's email.
type PendingInvitation struct {
	AppKey  string `json:"app_key"`
	AppName string `json:"app_name"`
}

// SocialCompleteResp is the response of POST /api/v1/auth/social/complete.
// Normal: the standard token shape. 2FA-enabled identity: mfa_required +
// mfa_token only (the session is completed via POST /api/v1/auth/login/2fa).
type SocialCompleteResp struct {
	AccessToken        string              `json:"access_token,omitempty"`
	RefreshToken       string              `json:"refresh_token,omitempty"`
	TokenType          string              `json:"token_type,omitempty"`
	ExpiresIn          int64               `json:"expires_in,omitempty"`
	Session            *SessionInfo        `json:"session,omitempty"`
	MfaRequired        bool                `json:"mfa_required,omitempty"`
	MfaToken           string              `json:"mfa_token,omitempty"`
	PendingInvitations []PendingInvitation `json:"pending_invitations"`
}

// SocialIdentityItem is one entry of GET /api/v1/me/social-identities.
type SocialIdentityItem struct {
	ID            string    `json:"id"`
	Provider      string    `json:"provider"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	DisplayName   string    `json:"display_name"`
	CreatedAt     time.Time `json:"created_at"`
}
