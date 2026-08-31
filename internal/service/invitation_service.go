package service

import (
	"context"
	"strings"
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

// InvitationService implements the public two-phase invitation flow
// (redeem -> accept) shared by logged-in identities and anonymous visitors.
type InvitationService interface {
	Redeem(ctx context.Context, req *dto.RedeemReq, identityID string) (*dto.InvitationPreview, error)
	Accept(ctx context.Context, req *dto.AcceptReq, actx *AuthContextInfo, device, ip string) (*dto.AcceptResp, error)
}

type invitationServiceImpl struct {
	c     container.Container
	token TokenService
}

// NewInvitationService builds the invitation service.
func NewInvitationService(c container.Container) InvitationService {
	return &invitationServiceImpl{c: c, token: NewTokenService(c)}
}

// resolvePending loads the pending invitation for a redeem code. All failure
// modes surface as one generic 404 to avoid leaking invitation state.
func (s *invitationServiceImpl) resolvePending(ctx context.Context, code string) (*model.Invitation, error) {
	if strings.TrimSpace(code) == "" {
		return nil, verrors.NotFoundError("invalid or expired invitation code")
	}
	invitation, err := s.c.InvitationRepo().FindByCodeHash(ctx, sha256Hex(code))
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("invalid or expired invitation code")
		}
		return nil, verrors.Wrap(err, "find invitation")
	}
	return invitation, nil
}

func (s *invitationServiceImpl) Redeem(ctx context.Context, req *dto.RedeemReq, identityID string) (*dto.InvitationPreview, error) {
	invitation, err := s.resolvePending(ctx, req.Code)
	if err != nil {
		return nil, err
	}
	app, err := s.c.AppRepo().FindByID(ctx, invitation.AppID)
	if err != nil {
		return nil, verrors.NotFoundError("invalid or expired invitation code")
	}
	roles := s.invitationRoles(ctx, jsonStringsOf(invitation.RoleIDs))
	// auto_provision: the caller is anonymous AND no identity holds the
	// invitation email yet.
	autoProvision := false
	if identityID == "" {
		if _, err := s.c.UserRepo().FindByEmail(ctx, invitation.Email); repository.IsNotFound(err) {
			autoProvision = true
		}
	}
	return &dto.InvitationPreview{
		AppKey:         app.Key,
		AppName:        app.Name,
		Email:          invitation.Email,
		Roles:          roles,
		InvitedByLabel: s.invitedByLabel(ctx, invitation.InvitedBy),
		ExpiresAt:      invitation.ExpiresAt,
		AutoProvision:  autoProvision,
	}, nil
}

// invitationRoles resolves the invitation's role ids to {code,name} pairs,
// keeping only roles that belong to the invitation's app.
func (s *invitationServiceImpl) invitationRoles(ctx context.Context, roleIDs []string) []dto.RoleSummary {
	out := make([]dto.RoleSummary, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		role, err := s.c.RoleRepo().FindByID(ctx, roleID)
		if err != nil {
			continue
		}
		out = append(out, dto.RoleSummary{Code: role.Code, Name: role.Name})
	}
	return out
}

func (s *invitationServiceImpl) invitedByLabel(ctx context.Context, invitedBy string) string {
	account, err := s.c.AccountRepo().FindByID(ctx, invitedBy)
	if err == nil {
		if account.DisplayName != nil && *account.DisplayName != "" {
			return *account.DisplayName
		}
		return account.Email
	}
	user, err := s.c.UserRepo().FindByID(ctx, invitedBy)
	if err == nil {
		if user.Nickname != nil && *user.Nickname != "" {
			return *user.Nickname
		}
		return user.Username
	}
	return ""
}

func (s *invitationServiceImpl) Accept(ctx context.Context, req *dto.AcceptReq, actx *AuthContextInfo, device, ip string) (*dto.AcceptResp, error) {
	invitation, err := s.resolvePending(ctx, req.Code)
	if err != nil {
		return nil, err
	}
	app, err := s.c.AppRepo().FindByID(ctx, invitation.AppID)
	if err != nil {
		return nil, verrors.NotFoundError("invalid or expired invitation code")
	}

	// Validate the invitation's roles up front (all must belong to the app).
	invitationRoleIDs := jsonStringsOf(invitation.RoleIDs)
	roleIDs := make([]string, 0, len(invitationRoleIDs))
	for _, roleID := range invitationRoleIDs {
		role, err := s.c.RoleRepo().FindByID(ctx, roleID)
		if err != nil || role.AppID != app.Id {
			return nil, verrors.BadRequestError("invitation references a role outside the app")
		}
		roleIDs = append(roleIDs, role.Id)
	}

	now := time.Now()
	var identityID string
	var newIdentity *model.User
	var passwordHash string

	switch {
	case actx != nil && actx.Kind == "identity":
		// Logged-in caller: bind the new account to their identity.
		user, err := s.c.UserRepo().FindByID(ctx, actx.UserID)
		if err != nil || user.Status != domain.UserStatusActive {
			return nil, verrors.ForbiddenError("identity must be active to accept invitations")
		}
		identityID = user.Id
		if req.NewPassword != "" {
			if err := password.ValidatePolicy(req.NewPassword); err != nil {
				return nil, err
			}
			hash, err := password.Hash(req.NewPassword, s.c.Cfg().Auth.BcryptCost)
			if err != nil {
				return nil, err
			}
			passwordHash = hash
		}
	case actx != nil && actx.Kind == "account":
		return nil, verrors.ForbiddenError("sign in with an identity token to accept invitations")
	default:
		// Anonymous caller: only possible when the invitation email has no
		// identity yet (auto-provision); the new password initializes BOTH
		// the identity and the account.
		_, err := s.c.UserRepo().FindByEmail(ctx, invitation.Email)
		switch {
		case err == nil:
			return nil, verrors.ForbiddenError("an identity with this email already exists, sign in first")
		case !repository.IsNotFound(err):
			return nil, verrors.Wrap(err, "find identity by email")
		}
		if req.NewPassword == "" {
			return nil, verrors.BadRequestError("new_password is required to create your identity")
		}
		if err := password.ValidatePolicy(req.NewPassword); err != nil {
			return nil, err
		}
		hash, err := password.Hash(req.NewPassword, s.c.Cfg().Auth.BcryptCost)
		if err != nil {
			return nil, err
		}
		passwordHash = hash
	}

	// Duplicate account check before entering the transaction.
	if _, err := s.c.AccountRepo().FindByAppAndEmail(ctx, app.Id, invitation.Email); err == nil {
		return nil, verrors.ConflictError("an account for this email already exists in the app")
	} else if !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find account")
	}

	var accountID string
	err = runInTx(s.c, func(r *txRepos) error {
		if identityID == "" {
			username, err := deriveUniqueUsername(ctx, r.users)
			if err != nil {
				return err
			}
			created := &model.User{
				BasePostgres:  vgorm.BasePostgres{Id: uuid.NewString()},
				Username:      username,
				Email:         invitation.Email,
				EmailVerified: true,
				PasswordHash:  &passwordHash,
				Status:        domain.UserStatusActive,
			}
			if err := r.users.Create(ctx, created); err != nil {
				return err
			}
			newIdentity = created
			identityID = created.Id
		}
		account := &model.Account{
			BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
			IdentityID:   identityID,
			AppID:        app.Id,
			Email:        invitation.Email,
			PasswordHash: &passwordHash,
			Status:       domain.AccountStatusActive,
			Source:       domain.AccountSourceInvite,
		}
		if err := r.accounts.Create(ctx, account); err != nil {
			return err
		}
		accountID = account.Id
		if err := r.invitations.UpdateFields(ctx, invitation.Id, map[string]any{
			"status":              domain.InvitationStatusAccepted,
			"accepted_at":         now,
			"accepted_account_id": accountID,
		}); err != nil {
			return err
		}
		for _, roleID := range roleIDs {
			if err := r.accountRole.Add(ctx, accountID, roleID, invitation.InvitedBy, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	writeAudit(ctx, s.c, ActorIdentity, identityID, app.OrgID, AuditInvitationAccepted, "invitation", invitation.Id,
		map[string]any{"app_key": app.Key, "account_id": accountID, "auto_provision": newIdentity != nil}, ip, device)

	// Incremental casbin sync for the freshly granted roles.
	for _, roleID := range roleIDs {
		role, err := s.c.RoleRepo().FindByID(ctx, roleID)
		if err != nil {
			continue
		}
		_ = syncAccountRoleBinding(ctx, s.c, accountID, app, role, true)
	}
	_ = casbinNotify(ctx, s.c, []string{app.Key})

	resp := &dto.AcceptResp{AccountID: accountID, AppKey: app.Key}
	if newIdentity != nil {
		account, err := s.c.AccountRepo().FindByID(ctx, accountID)
		if err != nil {
			return nil, verrors.Wrap(err, "reload account")
		}
		pair, err := s.token.AccountPair(ctx, account, app, newIdentity, device, ip)
		if err != nil {
			return nil, err
		}
		resp.AccessToken = pair.AccessToken
		resp.RefreshToken = pair.RefreshToken
		resp.TokenType = pair.TokenType
		resp.ExpiresIn = pair.ExpiresIn
	}
	return resp, nil
}
