package dto

import "time"

// ---------- admin oauth-client CRUD ----------

// OAuthClientItem is the admin representation of an OIDC client. The secret
// is never returned here (only the create response carries the plaintext
// secret exactly once).
type OAuthClientItem struct {
	ClientID     string    `json:"client_id"`
	AppKey       string    `json:"app_key"`
	Name         string    `json:"name"`
	ClientType   string    `json:"client_type"`
	GrantTypes   []string  `json:"grant_types"`
	RedirectURIs []string  `json:"redirect_uris"`
	Scopes       []string  `json:"scopes"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// CreateOAuthClientReq is the body of POST /api/v1/admin/apps/{appKey}/oauth-clients.
type CreateOAuthClientReq struct {
	Name         string   `json:"name" validate:"required,max=255"`
	ClientType   string   `json:"client_type" validate:"required,oneof=confidential public"`
	GrantTypes   []string `json:"grant_types" validate:"required,min=1,max=8"`
	RedirectURIs []string `json:"redirect_uris" validate:"max=32"`
	Scopes       []string `json:"scopes" validate:"max=32"`
}

// CreateOAuthClientResp is the 201 response of the create endpoint. The
// plaintext client_secret is shown exactly once (only its sha256 hash is
// stored); public clients get no secret.
type CreateOAuthClientResp struct {
	OAuthClientItem
	ClientSecret string `json:"client_secret,omitempty"`
}

// UpdateOAuthClientReq is the body of PATCH
// /api/v1/admin/apps/{appKey}/oauth-clients/{clientId}. Changing the status
// to disabled takes effect on the next policy reload (the Casbin loader
// skips inactive service clients).
type UpdateOAuthClientReq struct {
	Name         *string  `json:"name" validate:"omitempty,max=255"`
	Status       *string  `json:"status" validate:"omitempty,oneof=active disabled"`
	GrantTypes   []string `json:"grant_types" validate:"omitempty,min=1,max=8"`
	RedirectURIs []string `json:"redirect_uris" validate:"omitempty,max=32"`
	Scopes       []string `json:"scopes" validate:"omitempty,max=32"`
}

// ---------- SPA authorize ----------

// OAuthAuthorizeReq is the body of POST /api/v1/oauth/authorize (the
// SPA-friendly JSON variant; a center identity token is required). Passing
// account_id selects the workspace explicitly (workspace-picker semantics);
// without it the identity's unique account in the client's app is used, or
// one is auto-provisioned.
type OAuthAuthorizeReq struct {
	ClientID            string `json:"client_id" validate:"required,max=48"`
	RedirectURI         string `json:"redirect_uri" validate:"required,max=1024"`
	Scope               string `json:"scope" validate:"omitempty,max=512"`
	State               string `json:"state" validate:"omitempty,max=512"`
	CodeChallenge       string `json:"code_challenge" validate:"omitempty,max=128"`
	CodeChallengeMethod string `json:"code_challenge_method" validate:"omitempty,max=8"`
	Nonce               string `json:"nonce" validate:"omitempty,max=512"`
	AccountID           string `json:"account_id" validate:"omitempty,max=64"`
}

// OAuthAuthorizeResp is the response of POST /api/v1/oauth/authorize. The
// frontend navigates the browser to redirect_to (code+state+iss appended).
type OAuthAuthorizeResp struct {
	RedirectTo string `json:"redirect_to"`
}
