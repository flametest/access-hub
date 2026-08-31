package dto

// AuthzCheckReq is the body of POST /api/v1/authz/check. Identity-token
// callers must pass account_id (the workspace account to check for);
// account-token callers check their own subject. When Obj is empty the
// resource is resolved by (method, path) exact reverse lookup.
type AuthzCheckReq struct {
	App       string `json:"app" validate:"omitempty,max=64"`
	AccountID string `json:"account_id" validate:"omitempty"`
	Obj       string `json:"obj" validate:"omitempty,max=128"`
	Method    string `json:"method" validate:"omitempty,max=8"`
	Path      string `json:"path" validate:"omitempty,max=255"`
	Act       string `json:"act" validate:"omitempty,max=64"`
}

// AuthzCheckResp is the response of POST /api/v1/authz/check.
type AuthzCheckResp struct {
	Allowed bool  `json:"allowed"`
	Version int64 `json:"version"`
}
