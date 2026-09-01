package service

import (
	"context"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/password"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
)

// EmailCodePurposeAccountActivate is the activation-code purpose; its kv key
// embeds the app key (`email:code:account_activate:{app}:{email}`).
const EmailCodePurposeAccountActivate = "account_activate"

// AdminAccountService manages workspace accounts: provisioning, status,
// password resets, identity transfer, roles and direct grants.
type AdminAccountService interface {
	List(ctx context.Context, actor *AdminActor, appKey, q, status string) (*dto.AdminAccountPage, error)
	Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateAccountReq) (*dto.CreateAccountResp, error)
	Update(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.UpdateAccountReq) (*dto.AdminAccountItem, error)
	ResetPassword(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.ResetPasswordReq) error
	Transfer(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.TransferAccountReq) error
	SetRoles(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.SetAccountRolesReq) ([]dto.RoleSummary, error)
	ListGrants(ctx context.Context, actor *AdminActor, appKey, accountID string) ([]dto.GrantItem, error)
	AddGrant(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.AddGrantReq) (*dto.GrantItem, error)
	RemoveGrant(ctx context.Context, actor *AdminActor, appKey, accountID, grantID string) error
}

type adminAccountServiceImpl struct {
	c container.Container
}

// NewAdminAccountService builds the admin account service.
func NewAdminAccountService(c container.Container) AdminAccountService {
	return &adminAccountServiceImpl{c: c}
}

func (s *adminAccountServiceImpl) rolesOf(ctx context.Context, accountID string) []dto.RoleSummary {
	now := time.Now()
	out := make([]dto.RoleSummary, 0)
	bindings, err := s.c.AccountRoleRepo().ListByAccount(ctx, accountID)
	if err != nil {
		return out
	}
	for _, b := range bindings {
		if expired(b.ExpiresAt, now) {
			continue
		}
		out = append(out, dto.RoleSummary{Code: b.RoleCode, Name: b.RoleName})
	}
	return out
}

func (s *adminAccountServiceImpl) toItem(account *model.Account, roles []dto.RoleSummary) *dto.AdminAccountItem {
	return &dto.AdminAccountItem{
		ID:          account.Id,
		IdentityID:  account.IdentityID,
		Email:       account.Email,
		Username:    deref(account.Username),
		DisplayName: deref(account.DisplayName),
		Status:      account.Status,
		Source:      account.Source,
		Roles:       roles,
		LastLoginAt: account.LastLoginAt,
		CreatedAt:   account.CreatedAt,
	}
}

func (s *adminAccountServiceImpl) List(ctx context.Context, actor *AdminActor, appKey, q, status string) (*dto.AdminAccountPage, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	var qPtr, statusPtr *string
	if q != "" {
		qPtr = &q
	}
	if status != "" {
		statusPtr = &status
	}
	accounts, err := s.c.AccountRepo().ListByAppQuery(ctx, app.Id, qPtr, statusPtr)
	if err != nil {
		return nil, verrors.Wrap(err, "list accounts")
	}
	items := make([]dto.AdminAccountItem, 0, len(accounts))
	for _, account := range accounts {
		items = append(items, *s.toItem(account, s.rolesOf(ctx, account.Id)))
	}
	return &dto.AdminAccountPage{Items: items, Total: len(items)}, nil
}

// resolveAccount loads the account and asserts it belongs to the app.
func (s *adminAccountServiceImpl) resolveAccount(ctx context.Context, app *model.App, accountID string) (*model.Account, error) {
	account, err := s.c.AccountRepo().FindByID(ctx, accountID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("account not found")
		}
		return nil, verrors.Wrap(err, "find account")
	}
	if account.AppID != app.Id {
		return nil, verrors.NotFoundError("account not found")
	}
	return account, nil
}

// validateAppRoles ensures every role id belongs to the app.
func (s *adminAccountServiceImpl) validateAppRoles(ctx context.Context, app *model.App, roleIDs []string) ([]*model.Role, error) {
	roles := make([]*model.Role, 0, len(roleIDs))
	seen := make(map[string]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		role, err := s.c.RoleRepo().FindByID(ctx, id)
		if err != nil {
			if repository.IsNotFound(err) {
				return nil, verrors.BadRequestError("unknown role " + id)
			}
			return nil, verrors.Wrap(err, "find role")
		}
		if role.AppID != app.Id {
			return nil, verrors.BadRequestError("role does not belong to the app")
		}
		roles = append(roles, role)
	}
	return roles, nil
}

// issueAccountActivationEmail stores the activation code and emails it. The
// console mailer prints it; the integration tests inject a recording mailer.
func (s *adminAccountServiceImpl) issueAccountActivationEmail(ctx context.Context, app *model.App, email string) error {
	code, err := randomDigits(6)
	if err != nil {
		return verrors.InternalServerError("generate activation code")
	}
	cfg := s.c.Cfg().Auth
	key := "email:code:" + EmailCodePurposeAccountActivate + ":" + app.Key + ":" + email
	if err := s.c.KV().Set(ctx, key, sha256Hex(code), cfg.EmailCodeTTL); err != nil {
		return verrors.Wrap(err, "store activation code")
	}
	subject := "Activate your account"
	body := "Your activation code for " + app.Name + " is: " + code + "\n\nUse it at POST /api/v1/auth/accounts/activate to set your password."
	return s.c.Mailer().Send(ctx, email, subject, body)
}

// issueSetPasswordEmail emails the set-password code for a passwordless
// identity (admin-provisioning path).
func (s *adminAccountServiceImpl) issueSetPasswordEmail(ctx context.Context, email string) error {
	code, err := randomDigits(6)
	if err != nil {
		return verrors.InternalServerError("generate set-password code")
	}
	cfg := s.c.Cfg().Auth
	key := "email:code:" + EmailCodePurposeSetPassword + ":" + email
	if err := s.c.KV().Set(ctx, key, sha256Hex(code), cfg.EmailCodeTTL); err != nil {
		return verrors.Wrap(err, "store set-password code")
	}
	subject := "Set your Access-Hub password"
	body := "Your password setup code is: " + code + "\n\nUse it at POST /api/v1/auth/password/set."
	return s.c.Mailer().Send(ctx, email, subject, body)
}

func (s *adminAccountServiceImpl) Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateAccountReq) (*dto.CreateAccountResp, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	email := normalizeEmail(req.Email)
	if _, err := s.c.AccountRepo().FindByAppAndEmail(ctx, app.Id, email); err == nil {
		return nil, verrors.ConflictError("an account for this email already exists in the app")
	} else if !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find account")
	}
	roles, err := s.validateAppRoles(ctx, app, req.RoleIDs)
	if err != nil {
		return nil, err
	}

	// Resolve (or auto-provision) the identity bound to the account.
	identity, err := s.c.UserRepo().FindByEmail(ctx, email)
	if err != nil && !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find identity")
	}

	var account *model.Account
	activationSent := false
	if req.Password != "" {
		if err := password.ValidatePolicy(req.Password); err != nil {
			return nil, err
		}
		hash, err := password.Hash(req.Password, s.c.Cfg().Auth.BcryptCost)
		if err != nil {
			return nil, err
		}
		if identity == nil {
			// New identity inherits the given password (v6: both credentials
			// initialized at birth, independent afterwards).
			username, err := deriveUniqueUsername(ctx, s.c.UserRepo())
			if err != nil {
				return nil, err
			}
			identity = &model.User{
				BasePostgres:  vgorm.BasePostgres{Id: uuid.NewString()},
				Username:      username,
				Email:         email,
				EmailVerified: true,
				PasswordHash:  &hash,
				Status:        domain.UserStatusActive,
			}
			if err := s.c.UserRepo().Create(ctx, identity); err != nil {
				return nil, verrors.Wrap(err, "auto-provision identity")
			}
		}
		account = &model.Account{
			BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
			IdentityID:   identity.Id,
			AppID:        app.Id,
			Email:        email,
			PasswordHash: &hash,
			Status:       domain.AccountStatusActive,
			Source:       domain.AccountSourceProvisioned,
		}
	} else {
		if identity == nil {
			username, err := deriveUniqueUsername(ctx, s.c.UserRepo())
			if err != nil {
				return nil, err
			}
			identity = &model.User{
				BasePostgres:  vgorm.BasePostgres{Id: uuid.NewString()},
				Username:      username,
				Email:         email,
				EmailVerified: true,
				Status:        domain.UserStatusActive,
			}
			if err := s.c.UserRepo().Create(ctx, identity); err != nil {
				return nil, verrors.Wrap(err, "auto-provision identity")
			}
		}
		account = &model.Account{
			BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
			IdentityID:   identity.Id,
			AppID:        app.Id,
			Email:        email,
			PasswordHash: nil, // set at activation
			Status:       domain.AccountStatusPendingActivation,
			Source:       domain.AccountSourceProvisioned,
		}
	}
	if req.Username != "" {
		u := req.Username
		account.Username = &u
	}
	if req.DisplayName != "" {
		d := req.DisplayName
		account.DisplayName = &d
	}
	if err := s.c.AccountRepo().Create(ctx, account); err != nil {
		return nil, verrors.Wrap(err, "create account")
	}

	if req.Password == "" {
		// Both activation and (when needed) identity set-password emails.
		if err := s.issueAccountActivationEmail(ctx, app, email); err != nil {
			return nil, err
		}
		activationSent = true
		if identity.PasswordHash == nil || *identity.PasswordHash == "" {
			if err := s.issueSetPasswordEmail(ctx, email); err != nil {
				return nil, err
			}
		}
	}

	// Role bindings + incremental policy sync.
	for _, role := range roles {
		if err := s.c.AccountRoleRepo().Add(ctx, account.Id, role.Id, actor.AccountID, nil); err != nil {
			return nil, verrors.Wrap(err, "grant role")
		}
		_ = syncAccountRoleBinding(ctx, s.c, account.Id, app, role, true)
		writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditRoleGranted, "account", account.Id,
			map[string]any{"role": role.Code, "via": "account_provision"}, "", "")
	}

	return &dto.CreateAccountResp{AccountID: account.Id, ActivationSent: activationSent}, nil
}

func (s *adminAccountServiceImpl) Update(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.UpdateAccountReq) (*dto.AdminAccountItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	account, err := s.resolveAccount(ctx, app, accountID)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{}
	if req.Status != nil {
		fields["status"] = *req.Status
	}
	if req.DisplayName != nil {
		fields["display_name"] = *req.DisplayName
	}
	if len(fields) > 0 {
		if err := s.c.AccountRepo().UpdateFields(ctx, account.Id, fields); err != nil {
			return nil, verrors.Wrap(err, "update account")
		}
	}
	if req.Status != nil && *req.Status == domain.AccountStatusDisabled {
		if err := s.c.SessionRepo().RevokeAllForAccount(ctx, account.Id, nowUTC()); err != nil {
			return nil, verrors.Wrap(err, "revoke account sessions")
		}
	}
	updated, err := s.c.AccountRepo().FindByID(ctx, account.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "reload account")
	}
	return s.toItem(updated, s.rolesOf(ctx, account.Id)), nil
}

func (s *adminAccountServiceImpl) ResetPassword(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.ResetPasswordReq) error {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return err
	}
	account, err := s.resolveAccount(ctx, app, accountID)
	if err != nil {
		return err
	}
	if err := password.ValidatePolicy(req.NewPassword); err != nil {
		return err
	}
	hash, err := password.Hash(req.NewPassword, s.c.Cfg().Auth.BcryptCost)
	if err != nil {
		return err
	}
	if err := s.c.AccountRepo().UpdateFields(ctx, account.Id, map[string]any{"password_hash": hash}); err != nil {
		return verrors.Wrap(err, "reset account password")
	}
	if err := s.c.SessionRepo().RevokeAllForAccount(ctx, account.Id, nowUTC()); err != nil {
		return verrors.Wrap(err, "revoke account sessions")
	}
	writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditPasswordReset, "account", account.Id,
		map[string]any{"via": "admin"}, "", "")
	return nil
}

func (s *adminAccountServiceImpl) Transfer(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.TransferAccountReq) error {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return err
	}
	account, err := s.resolveAccount(ctx, app, accountID)
	if err != nil {
		return err
	}
	target, err := s.c.UserRepo().FindByEmail(ctx, normalizeEmail(req.IdentityEmail))
	if err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("no identity with this email")
		}
		return verrors.Wrap(err, "find identity")
	}
	if target.Status != domain.UserStatusActive {
		return verrors.ForbiddenError("target identity is disabled")
	}
	if target.Id == account.IdentityID {
		return verrors.ConflictError("account is already bound to this identity")
	}
	if err := s.c.AccountRepo().UpdateFields(ctx, account.Id, map[string]any{"identity_id": target.Id}); err != nil {
		return verrors.Wrap(err, "transfer account")
	}
	writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditAccountTransferred, "account", account.Id,
		map[string]any{"from_identity": account.IdentityID, "to_identity": target.Id}, "", "")
	return nil
}

func (s *adminAccountServiceImpl) SetRoles(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.SetAccountRolesReq) ([]dto.RoleSummary, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	account, err := s.resolveAccount(ctx, app, accountID)
	if err != nil {
		return nil, err
	}
	roles, err := s.validateAppRoles(ctx, app, req.RoleIDs)
	if err != nil {
		return nil, err
	}
	// Diff before/after for policy sync and audits.
	before, err := s.c.AccountRoleRepo().ListByAccount(ctx, account.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "list current roles")
	}
	beforeIDs := make(map[string]string, len(before)) // roleID -> code
	for _, b := range before {
		beforeIDs[b.RoleID] = b.RoleCode
	}
	afterIDs := make(map[string]string, len(roles))
	for _, role := range roles {
		afterIDs[role.Id] = role.Code
	}
	if err := s.c.AccountRoleRepo().SetForAccount(ctx, account.Id, keysOf(afterIDs), actor.AccountID); err != nil {
		return nil, verrors.Wrap(err, "replace account roles")
	}
	for roleID, code := range afterIDs {
		if _, had := beforeIDs[roleID]; had {
			continue
		}
		role := findRole(roles, roleID)
		_ = syncAccountRoleBinding(ctx, s.c, account.Id, app, role, true)
		writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditRoleGranted, "account", account.Id,
			map[string]any{"role": code}, "", "")
	}
	for roleID, code := range beforeIDs {
		if _, kept := afterIDs[roleID]; kept {
			continue
		}
		role, err := s.c.RoleRepo().FindByID(ctx, roleID)
		if err != nil {
			continue
		}
		_ = syncAccountRoleBinding(ctx, s.c, account.Id, app, role, false)
		writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditRoleRevoked, "account", account.Id,
			map[string]any{"role": code}, "", "")
	}
	return s.rolesOf(ctx, account.Id), nil
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func findRole(roles []*model.Role, id string) *model.Role {
	for _, r := range roles {
		if r.Id == id {
			return r
		}
	}
	return &model.Role{AppID: "", Scope: domain.RoleScopeGlobal}
}

// ---------- grants ----------

func (s *adminAccountServiceImpl) ListGrants(ctx context.Context, actor *AdminActor, appKey, accountID string) ([]dto.GrantItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	if _, err := s.resolveAccount(ctx, app, accountID); err != nil {
		return nil, err
	}
	rows, err := s.c.AccountGrantRepo().ListByAccountWithResource(ctx, accountID)
	if err != nil {
		return nil, verrors.Wrap(err, "list grants")
	}
	out := make([]dto.GrantItem, 0, len(rows))
	for _, row := range rows {
		grantedBy := ""
		if row.Grant.GrantedBy != nil {
			grantedBy = *row.Grant.GrantedBy
		}
		out = append(out, dto.GrantItem{
			ID:           row.Grant.Id,
			AccountID:    row.Grant.AccountID,
			ResourceID:   row.Grant.ResourceID,
			ResourceCode: row.ResourceCode,
			ResourceName: row.ResourceName,
			ResourceType: row.ResourceType,
			Effect:       row.Grant.Effect,
			GrantedBy:    grantedBy,
			GrantedAt:    row.Grant.GrantedAt,
			ExpiresAt:    row.Grant.ExpiresAt,
		})
	}
	return out, nil
}

// AddGrant grants (effect=allow) or blocks (effect=deny) one resource for an
// account. Deny grants sit above role allows in the priority ladder, so they
// win over every role binding.
func (s *adminAccountServiceImpl) AddGrant(ctx context.Context, actor *AdminActor, appKey, accountID string, req *dto.AddGrantReq) (*dto.GrantItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	account, err := s.resolveAccount(ctx, app, accountID)
	if err != nil {
		return nil, err
	}
	effect, err := normalizeBindingEffect(req.Effect)
	if err != nil {
		return nil, err
	}
	resource, err := s.c.ResourceRepo().FindByID(ctx, req.ResourceID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("resource not found")
		}
		return nil, verrors.Wrap(err, "find resource")
	}
	if resource.AppID != app.Id {
		return nil, verrors.BadRequestError("resource does not belong to the app")
	}
	grantID, err := s.c.AccountGrantRepo().Add(ctx, account.Id, resource.Id, actor.AccountID, effect, req.ExpiresAt)
	if err != nil {
		return nil, verrors.Wrap(err, "add grant")
	}
	_ = syncGrantRule(ctx, s.c, account.Id, app.Key, resource.Code, effect, true)
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditGrantAdded, "account", account.Id,
		map[string]any{"resource": resource.Code, "effect": effect}, "", "")
	return &dto.GrantItem{
		ID:           grantID,
		AccountID:    account.Id,
		ResourceID:   resource.Id,
		ResourceCode: resource.Code,
		ResourceName: resource.Name,
		ResourceType: resource.Type,
		Effect:       effect,
		GrantedBy:    actor.AccountID,
		GrantedAt:    time.Now(),
		ExpiresAt:    req.ExpiresAt,
	}, nil
}

func (s *adminAccountServiceImpl) RemoveGrant(ctx context.Context, actor *AdminActor, appKey, accountID, grantID string) error {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return err
	}
	account, err := s.resolveAccount(ctx, app, accountID)
	if err != nil {
		return err
	}
	grant, err := s.c.AccountGrantRepo().FindByID(ctx, grantID)
	if err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("grant not found")
		}
		return verrors.Wrap(err, "find grant")
	}
	if grant.AccountID != account.Id {
		return verrors.NotFoundError("grant not found")
	}
	resource, err := s.c.ResourceRepo().FindByID(ctx, grant.ResourceID)
	if err != nil {
		return verrors.Wrap(err, "find granted resource")
	}
	if err := s.c.AccountGrantRepo().RemoveByID(ctx, grantID); err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("grant not found")
		}
		return verrors.Wrap(err, "remove grant")
	}
	_ = syncGrantRule(ctx, s.c, account.Id, app.Key, resource.Code, grant.Effect, false)
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditGrantRemoved, "account", account.Id,
		map[string]any{"resource": resource.Code, "effect": grant.Effect}, "", "")
	return nil
}
