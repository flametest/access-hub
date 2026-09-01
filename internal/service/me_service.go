package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/password"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
)

// MeService implements the identity-scoped /me endpoints.
type MeService interface {
	GetMe(ctx context.Context, userID string) (*dto.Me, error)
	UpdateMe(ctx context.Context, actx *AuthContextInfo, req *dto.UpdateMeReq) (*dto.Me, error)
	ListMyOrgs(ctx context.Context, userID string) ([]dto.MyOrgItem, error)
	ListWorkspaces(ctx context.Context, userID string) ([]dto.WorkspaceItem, error)
	GetWorkspace(ctx context.Context, userID, accountID string) (*dto.WorkspaceItem, error)
	WorkspaceToken(ctx context.Context, userID, accountID, device, ip string) (*dto.WorkspaceTokenResp, error)
	Menus(ctx context.Context, actx *AuthContextInfo, appParam string) ([]*dto.MenuNode, error)
	Permissions(ctx context.Context, actx *AuthContextInfo, appParam string) (*dto.PermissionsResp, error)
	SigninMethods(ctx context.Context, userID string) ([]dto.SigninMethod, error)
	ListSessions(ctx context.Context, userID, currentSessionID string) ([]dto.SessionItem, error)
	RevokeSession(ctx context.Context, userID, sessionID string) error
	RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) error
	// 2FA self-service (M4).
	TwoFAStatus(ctx context.Context, userID string) (*dto.TwoFAStatusResp, error)
	TwoFAEnroll(ctx context.Context, userID string) (*dto.TwoFAEnrollResp, error)
	TwoFAConfirm(ctx context.Context, userID, code string) (*dto.TwoFAConfirmResp, error)
	TwoFADisable(ctx context.Context, userID, password string) error
}

// AuthContextInfo is the middleware-resolved caller view the services need
// (kept as a plain struct so services stay free of echo types).
type AuthContextInfo struct {
	Kind      string // "identity" | "account"
	UserID    string
	AccountID string
	Aud       string
	SessionID string
}

// SubjectUserID returns the caller's identity id for both token kinds.
func (a *AuthContextInfo) SubjectUserID() string {
	if a.Kind == "account" {
		return "" // not the identity id; account callers resolve via account
	}
	return a.UserID
}

type meServiceImpl struct {
	c     container.Container
	token TokenService
}

// NewMeService builds the me service.
func NewMeService(c container.Container) MeService {
	return &meServiceImpl{c: c, token: NewTokenService(c)}
}

func (s *meServiceImpl) GetMe(ctx context.Context, userID string) (*dto.Me, error) {
	user, err := s.c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return nil, verrors.NotFoundError("identity not found")
	}
	return toMe(user, twoFAConfirmed(ctx, s.c, userID)), nil
}

func (s *meServiceImpl) UpdateMe(ctx context.Context, actx *AuthContextInfo, req *dto.UpdateMeReq) (*dto.Me, error) {
	user, err := s.c.UserRepo().FindByID(ctx, actx.UserID)
	if err != nil {
		return nil, verrors.NotFoundError("identity not found")
	}
	fields := map[string]any{}
	if req.Nickname != nil {
		fields["nickname"] = *req.Nickname
	}
	if req.AvatarURL != nil {
		fields["avatar_url"] = *req.AvatarURL
	}
	if req.Password != "" {
		if user.PasswordHash == nil || *user.PasswordHash == "" {
			return nil, verrors.ForbiddenError("no password set yet, use the email set-password flow")
		}
		if err := password.Verify(*user.PasswordHash, req.CurrentPassword); err != nil {
			return nil, verrors.ForbiddenError("current password mismatch")
		}
		if err := password.ValidatePolicy(req.Password); err != nil {
			return nil, err
		}
		hash, err := password.Hash(req.Password, s.c.Cfg().Auth.BcryptCost)
		if err != nil {
			return nil, err
		}
		fields["password_hash"] = hash
		fields["must_change_password"] = false
	}
	if len(fields) > 0 {
		if err := s.c.UserRepo().UpdateFields(ctx, user.Id, fields); err != nil {
			return nil, verrors.Wrap(err, "update profile")
		}
	}
	if req.Password != "" {
		if err := s.token.RevokeAllIdentityExcept(ctx, user.Id, actx.SessionID); err != nil {
			return nil, err
		}
		writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditPasswordChanged, "user", user.Id,
			map[string]any{"via": "self"}, "", "")
	}
	updated, err := s.c.UserRepo().FindByID(ctx, user.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "reload profile")
	}
	return toMe(updated, twoFAConfirmed(ctx, s.c, actx.UserID)), nil
}

func (s *meServiceImpl) ListMyOrgs(ctx context.Context, userID string) ([]dto.MyOrgItem, error) {
	memberships, err := s.c.OrgMemberRepo().ListByUser(ctx, userID)
	if err != nil {
		return nil, verrors.Wrap(err, "list org memberships")
	}
	out := make([]dto.MyOrgItem, 0, len(memberships))
	for _, m := range memberships {
		org, err := s.c.OrgRepo().FindByID(ctx, m.OrgID)
		if err != nil {
			continue // soft-deleted org: skip
		}
		out = append(out, dto.MyOrgItem{Key: org.Key, Name: org.Name, OrgRole: m.OrgRole})
	}
	return out, nil
}

func (s *meServiceImpl) ListWorkspaces(ctx context.Context, userID string) ([]dto.WorkspaceItem, error) {
	accounts, err := s.c.AccountRepo().ListByIdentity(ctx, userID)
	if err != nil {
		return nil, verrors.Wrap(err, "list workspace accounts")
	}
	out := make([]dto.WorkspaceItem, 0, len(accounts))
	for _, account := range accounts {
		item, err := s.workspaceItem(ctx, account)
		if err != nil {
			continue
		}
		out = append(out, *item)
	}
	return out, nil
}

func (s *meServiceImpl) GetWorkspace(ctx context.Context, userID, accountID string) (*dto.WorkspaceItem, error) {
	account, err := s.ownedAccount(ctx, userID, accountID)
	if err != nil {
		return nil, err
	}
	return s.workspaceItem(ctx, account)
}

func (s *meServiceImpl) WorkspaceToken(ctx context.Context, userID, accountID, device, ip string) (*dto.WorkspaceTokenResp, error) {
	account, err := s.ownedAccount(ctx, userID, accountID)
	if err != nil {
		return nil, err
	}
	if account.Status != domain.AccountStatusActive {
		return nil, verrors.ForbiddenError("account is not active")
	}
	app, err := s.c.AppRepo().FindByID(ctx, account.AppID)
	if err != nil {
		return nil, verrors.Wrap(err, "find app")
	}
	identity, err := s.c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return nil, verrors.Wrap(err, "find identity")
	}
	pair, err := s.token.AccountPair(ctx, account, app, identity, device, ip)
	if err != nil {
		return nil, err
	}
	return &dto.WorkspaceTokenResp{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
		AccountID:    account.Id,
		AppKey:       app.Key,
	}, nil
}

// ownedAccount loads the account and asserts it belongs to the identity.
func (s *meServiceImpl) ownedAccount(ctx context.Context, userID, accountID string) (*model.Account, error) {
	account, err := s.c.AccountRepo().FindByID(ctx, accountID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("workspace not found")
		}
		return nil, verrors.Wrap(err, "find account")
	}
	if account.IdentityID != userID {
		return nil, verrors.NotFoundError("workspace not found")
	}
	return account, nil
}

func (s *meServiceImpl) workspaceItem(ctx context.Context, account *model.Account) (*dto.WorkspaceItem, error) {
	app, err := s.c.AppRepo().FindByID(ctx, account.AppID)
	if err != nil {
		return nil, err
	}
	orgKey, orgName := "", ""
	if app.OrgID != nil {
		if org, err := s.c.OrgRepo().FindByID(ctx, *app.OrgID); err == nil {
			orgKey, orgName = org.Key, org.Name
		}
	}
	now := time.Now()
	roles := make([]dto.RoleSummary, 0)
	bindings, err := s.c.AccountRoleRepo().ListByAccount(ctx, account.Id)
	if err == nil {
		for _, b := range bindings {
			if expired(b.ExpiresAt, now) {
				continue
			}
			roles = append(roles, dto.RoleSummary{Code: b.RoleCode, Name: b.RoleName})
		}
	}
	return &dto.WorkspaceItem{
		AccountID:   account.Id,
		AppKey:      app.Key,
		AppName:     app.Name,
		AppLogoURL:  deref(app.LogoURL),
		OrgKey:      orgKey,
		OrgName:     orgName,
		Email:       account.Email,
		DisplayName: deref(account.DisplayName),
		Status:      account.Status,
		Roles:       roles,
		LastLoginAt: account.LastLoginAt,
	}, nil
}

// resolveGrantedApp returns the app key and the subject accounts for
// menus/permissions. Identity callers get the union of their active accounts
// in the app; account callers are pinned to their own account and aud.
func (s *meServiceImpl) resolveGrantedApp(ctx context.Context, actx *AuthContextInfo, appParam string) (string, []*model.Account, error) {
	if actx.Kind == "account" {
		appKey := actx.Aud
		if appParam != "" && appParam != appKey {
			return "", nil, verrors.ForbiddenError("app does not match the token audience")
		}
		account, err := s.c.AccountRepo().FindByID(ctx, actx.AccountID)
		if err != nil {
			return "", nil, verrors.NotFoundError("account not found")
		}
		return appKey, []*model.Account{account}, nil
	}
	if appParam == "" {
		return "", nil, verrors.BadRequestError("app query parameter is required")
	}
	app, err := s.c.AppRepo().FindByKey(ctx, appParam)
	if err != nil {
		if repository.IsNotFound(err) {
			return "", nil, verrors.NotFoundError("app not found")
		}
		return "", nil, verrors.Wrap(err, "find app")
	}
	accounts, err := s.c.AccountRepo().ListByIdentity(ctx, actx.UserID)
	if err != nil {
		return "", nil, verrors.Wrap(err, "list accounts")
	}
	mine := make([]*model.Account, 0, 1)
	for _, a := range accounts {
		if a.AppID == app.Id && a.Status == domain.AccountStatusActive {
			mine = append(mine, a)
		}
	}
	return app.Key, mine, nil
}

// grantedCodeSet computes the permission codes from the business tables
// (role_resources of the account's roles + account_grants) — NOT casbin.
func (s *meServiceImpl) grantedCodeSet(ctx context.Context, accounts []*model.Account) (map[string]struct{}, error) {
	now := time.Now()
	codes := make(map[string]struct{})
	for _, account := range accounts {
		bindings, err := s.c.AccountRoleRepo().ListByAccount(ctx, account.Id)
		if err != nil {
			return nil, verrors.Wrap(err, "list account roles")
		}
		for _, b := range bindings {
			if expired(b.ExpiresAt, now) {
				continue
			}
			rows, err := s.c.RoleResourceRepo().ListByRoleWithResources(ctx, b.RoleID)
			if err != nil {
				return nil, verrors.Wrap(err, "list role resources")
			}
			for _, row := range rows {
				if row.ResourceStatus == domain.ResourceStatusActive {
					codes[row.ResourceCode] = struct{}{}
				}
			}
		}
		grants, err := s.c.AccountGrantRepo().ListByAccountWithResource(ctx, account.Id)
		if err != nil {
			return nil, verrors.Wrap(err, "list account grants")
		}
		for _, g := range grants {
			if expired(g.Grant.ExpiresAt, now) {
				continue
			}
			codes[g.ResourceCode] = struct{}{}
		}
	}
	return codes, nil
}

func (s *meServiceImpl) Menus(ctx context.Context, actx *AuthContextInfo, appParam string) ([]*dto.MenuNode, error) {
	appKey, accounts, err := s.resolveGrantedApp(ctx, actx, appParam)
	if err != nil {
		return nil, err
	}
	app, err := s.c.AppRepo().FindByKey(ctx, appKey)
	if err != nil {
		return nil, verrors.NotFoundError("app not found")
	}
	codes, err := s.grantedCodeSet(ctx, accounts)
	if err != nil {
		return nil, err
	}
	rows, err := s.c.ResourceRepo().ListByAppAndType(ctx, app.Id, domain.ResourceTypeMenu)
	if err != nil {
		return nil, verrors.Wrap(err, "list menus")
	}
	return buildMenuTree(rows, codes), nil
}

// buildMenuTree assembles the visible menu tree filtered by the granted code
// set: a node is included iff its code is granted; a parent is included iff
// any descendant survives the filter.
func buildMenuTree(rows []*model.Resource, granted map[string]struct{}) []*dto.MenuNode {
	byID := make(map[string]*model.Resource, len(rows))
	children := make(map[string][]*model.Resource, len(rows))
	var roots []*model.Resource
	for _, r := range rows {
		byID[r.Id] = r
	}
	for _, r := range rows {
		if r.ParentID != nil && byID[*r.ParentID] != nil {
			children[*r.ParentID] = append(children[*r.ParentID], r)
		} else {
			roots = append(roots, r)
		}
	}
	var build func(r *model.Resource) *dto.MenuNode
	build = func(r *model.Resource) *dto.MenuNode {
		node := &dto.MenuNode{
			ID:       r.Id,
			Code:     r.Code,
			Name:     r.Name,
			Path:     deref(r.RoutePath),
			Icon:     deref(r.Icon),
			Sort:     r.Sort,
			Children: []*dto.MenuNode{},
		}
		kids := children[r.Id]
		sort.SliceStable(kids, func(i, j int) bool { return kids[i].Sort < kids[j].Sort })
		for _, kid := range kids {
			if kid.Status != domain.ResourceStatusActive || !kid.Visible {
				continue
			}
			if child := build(kid); child != nil {
				node.Children = append(node.Children, child)
			}
		}
		_, grantedHere := granted[r.Code]
		if grantedHere || len(node.Children) > 0 {
			return node
		}
		return nil
	}
	sort.SliceStable(roots, func(i, j int) bool { return roots[i].Sort < roots[j].Sort })
	out := make([]*dto.MenuNode, 0, len(roots))
	for _, root := range roots {
		if root.Status != domain.ResourceStatusActive || !root.Visible {
			continue
		}
		if node := build(root); node != nil {
			out = append(out, node)
		}
	}
	return out
}

func (s *meServiceImpl) Permissions(ctx context.Context, actx *AuthContextInfo, appParam string) (*dto.PermissionsResp, error) {
	appKey, accounts, err := s.resolveGrantedApp(ctx, actx, appParam)
	if err != nil {
		return nil, err
	}
	codes, err := s.grantedCodeSet(ctx, accounts)
	if err != nil {
		return nil, err
	}
	version, err := casbinx.GetPolicyVersion(ctx, s.c.KV(), appKey)
	if err != nil {
		return nil, verrors.Wrap(err, "read policy version")
	}
	list := make([]string, 0, len(codes))
	for code := range codes {
		list = append(list, code)
	}
	sort.Strings(list)
	return &dto.PermissionsResp{App: appKey, Version: version, Permissions: list}, nil
}

func (s *meServiceImpl) SigninMethods(ctx context.Context, userID string) ([]dto.SigninMethod, error) {
	user, err := s.c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return nil, verrors.NotFoundError("identity not found")
	}
	identities, err := s.c.IdentityRepo().ListByUser(ctx, userID)
	if err != nil {
		return nil, verrors.Wrap(err, "list social identities")
	}
	methods := make([]dto.SigninMethod, 0, 1+len(identities))
	enabled := user.PasswordHash != nil && *user.PasswordHash != ""
	detail := ""
	if enabled {
		detail = user.Email
	}
	methods = append(methods, dto.SigninMethod{
		Type:    "password",
		Label:   "Password",
		Detail:  detail,
		Enabled: enabled,
	})
	// Social bindings (M5): every stored identity is an enabled method.
	for _, row := range identities {
		methodDetail := deref(row.Email)
		if methodDetail == "" {
			methodDetail = deref(row.DisplayName)
		}
		label := domain.SocialProviderLabels[row.Provider]
		if label == "" {
			label = row.Provider
		}
		methods = append(methods, dto.SigninMethod{
			Type:    row.Provider,
			Label:   label,
			Detail:  methodDetail,
			Enabled: true,
		})
	}
	return methods, nil
}

func (s *meServiceImpl) ListSessions(ctx context.Context, userID, currentSessionID string) ([]dto.SessionItem, error) {
	sessions, err := s.c.SessionRepo().ListByUser(ctx, userID)
	if err != nil {
		return nil, verrors.Wrap(err, "list sessions")
	}
	appKeys := make(map[string]string)
	out := make([]dto.SessionItem, 0, len(sessions))
	for _, sess := range sessions {
		appKey := ""
		if sess.AppID != nil {
			if k, ok := appKeys[*sess.AppID]; ok {
				appKey = k
			} else if app, err := s.c.AppRepo().FindByID(ctx, *sess.AppID); err == nil {
				appKey = app.Key
				appKeys[*sess.AppID] = app.Key
			}
		}
		out = append(out, dto.SessionItem{
			ID:            sess.Id,
			Scope:         sess.Scope,
			AppKey:        appKey,
			Device:        deref(sess.Device),
			IP:            deref(sess.IP),
			LastUsedAt:    sess.LastUsedAt,
			RotationCount: sess.RotationCount,
			CreatedAt:     sess.CreatedAt,
			ExpiresAt:     sess.ExpiresAt,
			Current:       sess.Id == currentSessionID,
		})
	}
	return out, nil
}

func (s *meServiceImpl) RevokeSession(ctx context.Context, userID, sessionID string) error {
	sess, err := s.c.SessionRepo().FindByID(ctx, sessionID)
	if err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("session not found")
		}
		return verrors.Wrap(err, "find session")
	}
	if sess.UserID != userID {
		return verrors.NotFoundError("session not found")
	}
	return s.token.RevokeSession(ctx, sessionID)
}

func (s *meServiceImpl) RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) error {
	return s.token.RevokeAllIdentityExcept(ctx, userID, currentSessionID)
}

// ---------- 2FA self-service ----------

// TwoFAStatus implements GET /api/v1/me/2fa/status.
func (s *meServiceImpl) TwoFAStatus(ctx context.Context, userID string) (*dto.TwoFAStatusResp, error) {
	enabled, confirmed, err := LookupTwoFAStatus(ctx, s.c, userID)
	if err != nil {
		return nil, err
	}
	return &dto.TwoFAStatusResp{Enabled: enabled, Confirmed: confirmed}, nil
}

// TwoFAEnroll implements POST /api/v1/me/2fa/enroll.
func (s *meServiceImpl) TwoFAEnroll(ctx context.Context, userID string) (*dto.TwoFAEnrollResp, error) {
	user, err := s.c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return nil, verrors.NotFoundError("identity not found")
	}
	secret, uri, err := StartTwoFAEnroll(ctx, s.c, userID, user.Email)
	if err != nil {
		return nil, err
	}
	return &dto.TwoFAEnrollResp{Secret: secret, OtpauthURI: uri}, nil
}

// TwoFAConfirm implements POST /api/v1/me/2fa/confirm.
func (s *meServiceImpl) TwoFAConfirm(ctx context.Context, userID, code string) (*dto.TwoFAConfirmResp, error) {
	codes, err := ConfirmTwoFAEnroll(ctx, s.c, userID, code)
	if err != nil {
		return nil, err
	}
	return &dto.TwoFAConfirmResp{BackupCodes: codes}, nil
}

// TwoFADisable implements POST /api/v1/me/2fa/disable.
func (s *meServiceImpl) TwoFADisable(ctx context.Context, userID, pwd string) error {
	return DisableTwoFA(ctx, s.c, userID, pwd)
}

// grantedCodesFor accounts helper reused by the admin account view.
func formatAccountIdentifier(account *model.Account) string {
	if account.Username != nil && strings.TrimSpace(*account.Username) != "" {
		return *account.Username
	}
	return fmt.Sprintf("%s", account.Email)
}
