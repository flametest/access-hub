package dto

import "time"

// RedeemReq is the body of POST /api/v1/invitations/redeem.
type RedeemReq struct {
	Code string `json:"code" validate:"required"`
}

// InvitationPreview is the response of POST /api/v1/invitations/redeem: the
// confirm-screen payload (only returned for a valid pending code).
type InvitationPreview struct {
	AppKey         string        `json:"app_key"`
	AppName        string        `json:"app_name"`
	Email          string        `json:"email"`
	Roles          []RoleSummary `json:"roles"`
	InvitedByLabel string        `json:"invited_by_label"`
	ExpiresAt      time.Time     `json:"expires_at"`
	AutoProvision  bool          `json:"auto_provision"`
}

// AcceptReq is the body of POST /api/v1/invitations/accept. NewPassword is
// required when the caller is anonymous (auto-provision path).
type AcceptReq struct {
	Code        string `json:"code" validate:"required"`
	NewPassword string `json:"new_password" validate:"omitempty"`
}

// AcceptResp is the response of POST /api/v1/invitations/accept. Token fields
// are present only when a new identity was auto-provisioned (auto-login).
type AcceptResp struct {
	AccountID    string `json:"account_id"`
	AppKey       string `json:"app_key"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}
