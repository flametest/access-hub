package dto

import "time"

// ---------- orgs ----------

// OrgItem is the admin representation of an org.
type OrgItem struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateOrgReq is the body of POST /api/v1/admin/orgs.
type CreateOrgReq struct {
	Key  string `json:"key" validate:"required,min=2,max=64"`
	Name string `json:"name" validate:"required,max=255"`
}

// UpdateOrgReq is the body of PATCH /api/v1/admin/orgs/{key}.
type UpdateOrgReq struct {
	Name   *string `json:"name" validate:"omitempty,max=255"`
	Status *string `json:"status" validate:"omitempty,oneof=active disabled"`
}

// OrgMemberItem is one entry of GET /api/v1/admin/orgs/{key}/members.
type OrgMemberItem struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	OrgRole  string `json:"org_role"`
}

// AddOrgMemberReq is the body of POST /api/v1/admin/orgs/{key}/members
// (email or user_id must be provided).
type AddOrgMemberReq struct {
	Email   string `json:"email" validate:"omitempty,email,max=255"`
	UserID  string `json:"user_id" validate:"omitempty"`
	OrgRole string `json:"org_role" validate:"required,oneof=owner admin member"`
}

// ---------- apps ----------

// AppItem is the admin representation of an app.
type AppItem struct {
	ID          string    `json:"id"`
	Key         string    `json:"key"`
	OrgID       *string   `json:"org_id"`
	OrgKey      string    `json:"org_key"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	LogoURL     string    `json:"logo_url"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateAppReq is the body of POST /api/v1/admin/apps. OrgKey is required
// unless the caller holds platform rights.
type CreateAppReq struct {
	Key         string `json:"key" validate:"required,min=2,max=64"`
	OrgKey      string `json:"org_key" validate:"omitempty,max=64"`
	Name        string `json:"name" validate:"required,max=255"`
	Type        string `json:"type" validate:"omitempty,oneof=web native service"`
	Description string `json:"description" validate:"omitempty,max=1024"`
	LogoURL     string `json:"logo_url" validate:"omitempty,max=1024"`
}

// UpdateAppReq is the body of PATCH /api/v1/admin/apps/{appKey}.
type UpdateAppReq struct {
	Name        *string `json:"name" validate:"omitempty,max=255"`
	Description *string `json:"description" validate:"omitempty,max=1024"`
	LogoURL     *string `json:"logo_url" validate:"omitempty,max=1024"`
	Status      *string `json:"status" validate:"omitempty,oneof=active disabled"`
}

// ---------- users (identities) ----------

// AdminUserItem is one entry of GET /api/v1/admin/users.
type AdminUserItem struct {
	ID            string     `json:"id"`
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	Nickname      string     `json:"nickname"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at"`
}

// AdminUserPage is the response of GET /api/v1/admin/users.
type AdminUserPage struct {
	Items    []AdminUserItem `json:"items"`
	Total    int64           `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
}

// UpdateUserReq is the body of PATCH /api/v1/admin/users/{id}.
type UpdateUserReq struct {
	Status string `json:"status" validate:"required,oneof=active disabled"`
}

// ResetPasswordReq is the body of the admin reset-password endpoints.
type ResetPasswordReq struct {
	NewPassword string `json:"new_password" validate:"required"`
}

// ---------- accounts ----------

// AdminAccountItem is the admin representation of a workspace account.
type AdminAccountItem struct {
	ID          string        `json:"id"`
	IdentityID  string        `json:"identity_id"`
	Email       string        `json:"email"`
	Username    string        `json:"username"`
	DisplayName string        `json:"display_name"`
	Status      string        `json:"status"`
	Source      string        `json:"source"`
	Roles       []RoleSummary `json:"roles"`
	LastLoginAt *time.Time    `json:"last_login_at"`
	CreatedAt   time.Time     `json:"created_at"`
}

// AdminAccountPage is the response of GET /api/v1/admin/apps/{appKey}/accounts.
type AdminAccountPage struct {
	Items    []AdminAccountItem `json:"items"`
	Total    int                `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"page_size"`
}

// CreateAccountReq is the body of POST /api/v1/admin/apps/{appKey}/accounts.
// With a password the account is created active; without one it is created
// pending_activation and an activation email is sent.
type CreateAccountReq struct {
	Email       string   `json:"email" validate:"required,email,max=255"`
	Username    string   `json:"username" validate:"omitempty,max=64"`
	DisplayName string   `json:"display_name" validate:"omitempty,max=255"`
	RoleIDs     []string `json:"role_ids" validate:"omitempty,dive"`
	Password    string   `json:"password" validate:"omitempty"`
}

// CreateAccountResp is the response of POST /api/v1/admin/apps/{appKey}/accounts.
type CreateAccountResp struct {
	AccountID      string `json:"account_id"`
	ActivationSent bool   `json:"activation_sent"`
}

// UpdateAccountReq is the body of PATCH /api/v1/admin/apps/{appKey}/accounts/{accountId}.
type UpdateAccountReq struct {
	Status      *string `json:"status" validate:"omitempty,oneof=pending_activation active disabled"`
	DisplayName *string `json:"display_name" validate:"omitempty,max=255"`
}

// TransferAccountReq is the body of POST .../accounts/{accountId}/transfer.
type TransferAccountReq struct {
	IdentityEmail string `json:"identity_email" validate:"required,email,max=255"`
}

// SetAccountRolesReq is the body of PUT .../accounts/{accountId}/roles
// (an empty list revokes every role).
type SetAccountRolesReq struct {
	RoleIDs []string `json:"role_ids" validate:"omitempty,dive"`
}

// ---------- grants ----------

// GrantItem is one entry of GET .../accounts/{accountId}/grants.
type GrantItem struct {
	ID           string     `json:"id"`
	AccountID    string     `json:"account_id"`
	ResourceID   string     `json:"resource_id"`
	ResourceCode string     `json:"resource_code"`
	ResourceName string     `json:"resource_name"`
	ResourceType string     `json:"resource_type"`
	Effect       string     `json:"effect"`
	GrantedBy    string     `json:"granted_by"`
	GrantedAt    time.Time  `json:"granted_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

// AddGrantReq is the body of POST .../accounts/{accountId}/grants.
// Effect is allow|deny (M6; default allow — a deny grant blocks the resource
// for the account regardless of role bindings).
type AddGrantReq struct {
	ResourceID string     `json:"resource_id" validate:"required"`
	ExpiresAt  *time.Time `json:"expires_at"`
	Effect     string     `json:"effect" validate:"omitempty,oneof=allow deny"`
}

// ---------- invitations (admin) ----------

// AdminInvitationItem is the admin representation of an invitation.
type AdminInvitationItem struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id"`
	Email      string     `json:"email"`
	RoleIDs    []string   `json:"role_ids"`
	Status     string     `json:"status"`
	InvitedBy  string     `json:"invited_by"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

// CreateInvitationReq is the body of POST /api/v1/admin/apps/{appKey}/invitations.
type CreateInvitationReq struct {
	Email    string   `json:"email" validate:"required,email,max=255"`
	RoleIDs  []string `json:"role_ids" validate:"required,min=1,dive"`
	TTLHours int      `json:"ttl_hours" validate:"omitempty,min=1,max=720"`
}

// ---------- resources ----------

// AdminResourceItem is the admin representation of a resource tree node.
// For menu resources the nav path is exposed as "path" (stored in the
// route_path column); api resources carry method + route_path.
type AdminResourceItem struct {
	ID        string               `json:"id"`
	ParentID  *string              `json:"parent_id"`
	Type      string               `json:"type"`
	Code      string               `json:"code"`
	Name      string               `json:"name"`
	Sort      int                  `json:"sort"`
	Status    string               `json:"status"`
	Visible   bool                 `json:"visible"`
	Icon      string               `json:"icon"`
	Method    string               `json:"method"`
	RoutePath string               `json:"route_path"`
	Path      string               `json:"path"`
	Children  []*AdminResourceItem `json:"children"`
}

// CreateResourceReq is the body of POST /api/v1/admin/apps/{appKey}/resources.
type CreateResourceReq struct {
	Type      string `json:"type" validate:"required,oneof=menu api button"`
	Code      string `json:"code" validate:"required,max=128"`
	Name      string `json:"name" validate:"required,max=255"`
	ParentID  string `json:"parent_id" validate:"omitempty"`
	Path      string `json:"path" validate:"omitempty,max=255"`
	Icon      string `json:"icon" validate:"omitempty,max=128"`
	Sort      *int   `json:"sort" validate:"omitempty"`
	Visible   *bool  `json:"visible" validate:"omitempty"`
	Method    string `json:"method" validate:"omitempty,max=8"`
	RoutePath string `json:"route_path" validate:"omitempty,max=255"`
	Status    string `json:"status" validate:"omitempty,oneof=active disabled"`
}

// UpdateResourceReq is the body of PATCH .../resources/{resourceId}.
type UpdateResourceReq struct {
	Name      *string `json:"name" validate:"omitempty,max=255"`
	ParentID  *string `json:"parent_id" validate:"omitempty"`
	Path      *string `json:"path" validate:"omitempty,max=255"`
	Icon      *string `json:"icon" validate:"omitempty,max=128"`
	Sort      *int    `json:"sort" validate:"omitempty"`
	Visible   *bool   `json:"visible" validate:"omitempty"`
	Method    *string `json:"method" validate:"omitempty,max=8"`
	RoutePath *string `json:"route_path" validate:"omitempty,max=255"`
	Status    *string `json:"status" validate:"omitempty,oneof=active disabled"`
}

// BatchResourceItem is one entry of PUT .../resources:batch.
type BatchResourceItem struct {
	Code       string `json:"code" validate:"required,max=128"`
	Name       string `json:"name" validate:"required,max=255"`
	Type       string `json:"type" validate:"required,oneof=menu api button"`
	ParentCode string `json:"parent_code" validate:"omitempty,max=128"`
	Path       string `json:"path" validate:"omitempty,max=255"`
	Icon       string `json:"icon" validate:"omitempty,max=128"`
	Sort       *int   `json:"sort" validate:"omitempty"`
	Visible    *bool  `json:"visible" validate:"omitempty"`
	Method     string `json:"method" validate:"omitempty,max=8"`
	RoutePath  string `json:"route_path" validate:"omitempty,max=255"`
	Status     string `json:"status" validate:"omitempty,oneof=active disabled"`
}

// BatchResourcesReq is the body of PUT /api/v1/admin/apps/{appKey}/resources:batch.
type BatchResourcesReq struct {
	Items []BatchResourceItem `json:"items" validate:"required,min=1,dive"`
}

// BatchResourcesResp is the response of PUT .../resources:batch.
type BatchResourcesResp struct {
	Created  int `json:"created"`
	Updated  int `json:"updated"`
	Disabled int `json:"disabled"`
}

// ---------- roles ----------

// AdminRoleItem is the admin representation of a role.
type AdminRoleItem struct {
	ID        string    `json:"id"`
	AppID     string    `json:"app_id"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	BuiltIn   bool      `json:"built_in"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateRoleReq is the body of POST /api/v1/admin/apps/{appKey}/roles.
type CreateRoleReq struct {
	Code  string `json:"code" validate:"required,min=2,max=64"`
	Name  string `json:"name" validate:"required,max=255"`
	Scope string `json:"scope" validate:"omitempty,oneof=app global"`
}

// UpdateRoleReq is the body of PATCH /api/v1/admin/apps/{appKey}/roles/{roleId}.
type UpdateRoleReq struct {
	Name *string `json:"name" validate:"omitempty,max=255"`
}

// SetRoleResourceItem is one entry of SetRoleResourcesReq.Items: the effect
// (allow|deny) to persist for the resource binding (M6 deny enablement).
type SetRoleResourceItem struct {
	ResourceID string `json:"resource_id" validate:"required"`
	Effect     string `json:"effect" validate:"omitempty,oneof=allow deny"`
}

// SetRoleResourcesReq is the body of PUT .../roles/{roleId}/resources. Two
// shapes are accepted (M6):
//   - {"resource_ids": ["id", ...]} — legacy all-allow form;
//   - {"items": [{"resource_id": "id", "effect": "allow|deny"}, ...]}.
//
// Providing both non-empty is rejected to avoid ambiguity.
type SetRoleResourcesReq struct {
	ResourceIDs []string              `json:"resource_ids" validate:"omitempty,dive"`
	Items       []SetRoleResourceItem `json:"items" validate:"omitempty,dive"`
}

// RoleResourceBindingItem is one current binding of GET
// /api/v1/admin/apps/{appKey}/roles/{roleId}/resources (effect included).
type RoleResourceBindingItem struct {
	ResourceID string `json:"resource_id"`
	Effect     string `json:"effect"`
	Code       string `json:"code"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Status     string `json:"status"`
}

// ---------- audit logs ----------

// AuditLogItem is one entry of GET /api/v1/admin/audit-logs.
type AuditLogItem struct {
	ID         string    `json:"id"`
	ActorType  string    `json:"actor_type"`
	ActorID    string    `json:"actor_id"`
	OrgID      string    `json:"org_id"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Detail     string    `json:"detail"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
}

// AuditLogPage is the response of GET /api/v1/admin/audit-logs.
type AuditLogPage struct {
	Items    []AuditLogItem `json:"items"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

// AuditActionCount is one action group of the audit summary.
type AuditActionCount struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

// AuditDailyCount is one day bucket of the audit summary (Date is
// "YYYY-MM-DD" UTC).
type AuditDailyCount struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// AuditActorCount is one actor group of the audit summary.
type AuditActorCount struct {
	ActorType string `json:"actor_type"`
	ActorID   string `json:"actor_id"`
	Count     int64  `json:"count"`
}

// AuditSummaryResp is the response of GET /api/v1/admin/audit-logs/summary
// (M6): grouped counts over the trailing `days` window (clamped 1..90).
type AuditSummaryResp struct {
	Days      int                `json:"days"`
	ByAction  []AuditActionCount `json:"by_action"`
	Daily     []AuditDailyCount  `json:"daily"`
	TopActors []AuditActorCount  `json:"top_actors"`
}

// ---------- custom rules (M6) ----------

// CustomRuleItem is the admin representation of a per-app ABAC rule.
type CustomRuleItem struct {
	ID        string    `json:"id"`
	AppID     string    `json:"app_id"`
	AppKey    string    `json:"app_key"`
	Name      string    `json:"name"`
	Expr      string    `json:"expr"`
	Effect    string    `json:"effect"`
	Priority  int       `json:"priority"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateCustomRuleReq is the body of POST /api/v1/admin/apps/{appKey}/custom-rules.
// The expression is validated against the ABAC env ({sub, dom, obj, act,
// roles, now}) at create time; an invalid expression is a 400.
type CreateCustomRuleReq struct {
	Name     string `json:"name" validate:"required,max=255"`
	Expr     string `json:"expr" validate:"required,max=4096"`
	Effect   string `json:"effect" validate:"required,oneof=allow deny"`
	Priority *int   `json:"priority" validate:"omitempty,min=1,max=100"`
	Status   string `json:"status" validate:"omitempty,oneof=active disabled"`
}

// UpdateCustomRuleReq is the body of PATCH .../custom-rules/{ruleId}; every
// changed field re-validates and re-syncs the policy set.
type UpdateCustomRuleReq struct {
	Name     *string `json:"name" validate:"omitempty,max=255"`
	Expr     *string `json:"expr" validate:"omitempty,max=4096"`
	Effect   *string `json:"effect" validate:"omitempty,oneof=allow deny"`
	Priority *int    `json:"priority" validate:"omitempty,min=1,max=100"`
	Status   *string `json:"status" validate:"omitempty,oneof=active disabled"`
}

// TestCustomRuleReq is the body of POST .../custom-rules/test (dry-run,
// nothing persisted). Obj defaults to "test:obj", act to "*".
type TestCustomRuleReq struct {
	Expr string `json:"expr" validate:"required,max=4096"`
	Obj  string `json:"obj" validate:"omitempty,max=128"`
	Act  string `json:"act" validate:"omitempty,max=64"`
}

// CustomRuleTestResp is the response of the dry-run endpoint: the boolean
// outcome and, when the expression failed to compile/evaluate, the error
// message (allowed=false, fail-close).
type CustomRuleTestResp struct {
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}
