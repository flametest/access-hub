package service

import (
	"context"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
)

// defaultInvitationTTL is the invitation validity when ttl_hours is omitted.
const defaultInvitationTTL = 72 * time.Hour

// AdminInvitationService manages app invitations.
type AdminInvitationService interface {
	Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateInvitationReq) (*dto.AdminInvitationItem, error)
	List(ctx context.Context, actor *AdminActor, appKey, status string) ([]dto.AdminInvitationItem, error)
	Revoke(ctx context.Context, actor *AdminActor, appKey, invitationID string) error
}

type adminInvitationServiceImpl struct {
	c container.Container
}

// NewAdminInvitationService builds the admin invitation service.
func NewAdminInvitationService(c container.Container) AdminInvitationService {
	return &adminInvitationServiceImpl{c: c}
}

func (s *adminInvitationServiceImpl) toItem(invitation *model.Invitation) dto.AdminInvitationItem {
	return dto.AdminInvitationItem{
		ID:         invitation.Id,
		AppID:      invitation.AppID,
		Email:      invitation.Email,
		RoleIDs:    invitationRoleIDs(invitation.RoleIDs),
		Status:     invitation.Status,
		InvitedBy:  invitation.InvitedBy,
		ExpiresAt:  invitation.ExpiresAt,
		AcceptedAt: invitation.AcceptedAt,
		CreatedAt:  invitation.CreatedAt,
	}
}

func (s *adminInvitationServiceImpl) Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateInvitationReq) (*dto.AdminInvitationItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	// All roles must belong to the app.
	for _, roleID := range req.RoleIDs {
		role, err := s.c.RoleRepo().FindByID(ctx, roleID)
		if err != nil {
			if repository.IsNotFound(err) {
				return nil, verrors.BadRequestError("unknown role " + roleID)
			}
			return nil, verrors.Wrap(err, "find role")
		}
		if role.AppID != app.Id {
			return nil, verrors.BadRequestError("role does not belong to the app")
		}
	}
	email := normalizeEmail(req.Email)
	code, err := randomToken()
	if err != nil {
		return nil, verrors.InternalServerError("generate invitation code")
	}
	ttl := defaultInvitationTTL
	if req.TTLHours > 0 {
		ttl = time.Duration(req.TTLHours) * time.Hour
	}
	invitation := &model.Invitation{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		AppID:        app.Id,
		Email:        email,
		RoleIDs:      roleIDsJSON(req.RoleIDs),
		InvitedBy:    actor.AccountID,
		CodeHash:     sha256Hex(code),
		ExpiresAt:    time.Now().Add(ttl),
		Status:       domain.InvitationStatusPending,
	}
	if err := s.c.InvitationRepo().Create(ctx, invitation); err != nil {
		return nil, verrors.Wrap(err, "create invitation")
	}
	subject := "You are invited to " + app.Name
	body := "You have been invited to " + app.Name + " with the roles: " + joinCodes(ctx, s.c, req.RoleIDs) + ".\n\n" +
		"Redeem this invitation code at POST /api/v1/invitations/redeem:\n" + code + "\n\n" +
		"The code expires at " + invitation.ExpiresAt.Format(time.RFC3339) + "."
	if err := s.c.Mailer().Send(ctx, email, subject, body); err != nil {
		return nil, verrors.Wrap(err, "send invitation email")
	}
	writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditInvitationCreated, "invitation", invitation.Id,
		map[string]any{"app_key": app.Key, "email": email}, "", "")
	item := s.toItem(invitation)
	return &item, nil
}

func joinCodes(ctx context.Context, c container.Container, roleIDs []string) string {
	out := ""
	for i, id := range roleIDs {
		if i > 0 {
			out += ", "
		}
		if role, err := c.RoleRepo().FindByID(ctx, id); err == nil {
			out += role.Code
		} else {
			out += id
		}
	}
	return out
}

// invitationRoleIDs decodes the jsonb role_ids column, tolerating nil.
func invitationRoleIDs(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := jsonUnmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// roleIDsJSON encodes the role id list for the jsonb column.
func roleIDsJSON(ids []string) []byte {
	if ids == nil {
		ids = []string{}
	}
	raw, err := jsonMarshal(ids)
	if err != nil {
		return []byte("[]")
	}
	return raw
}

func (s *adminInvitationServiceImpl) List(ctx context.Context, actor *AdminActor, appKey, status string) ([]dto.AdminInvitationItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	invitations, err := s.c.InvitationRepo().ListByApp(ctx, app.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "list invitations")
	}
	out := make([]dto.AdminInvitationItem, 0, len(invitations))
	for _, invitation := range invitations {
		if status != "" && invitation.Status != status {
			continue
		}
		out = append(out, s.toItem(invitation))
	}
	return out, nil
}

func (s *adminInvitationServiceImpl) Revoke(ctx context.Context, actor *AdminActor, appKey, invitationID string) error {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return err
	}
	invitation, err := s.c.InvitationRepo().FindByID(ctx, invitationID)
	if err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("invitation not found")
		}
		return verrors.Wrap(err, "find invitation")
	}
	if invitation.AppID != app.Id {
		return verrors.NotFoundError("invitation not found")
	}
	if invitation.Status != domain.InvitationStatusPending {
		return verrors.ConflictError("invitation is not pending")
	}
	if err := s.c.InvitationRepo().UpdateFields(ctx, invitation.Id, map[string]any{
		"status": domain.InvitationStatusRevoked,
	}); err != nil {
		return verrors.Wrap(err, "revoke invitation")
	}
	writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditInvitationRevoked, "invitation", invitation.Id,
		map[string]any{"app_key": app.Key}, "", "")
	return nil
}
