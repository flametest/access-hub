package domain

import (
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
)

// Invitation status values (invitations.status).
const (
	InvitationStatusPending  = "pending"
	InvitationStatusAccepted = "accepted"
	InvitationStatusRevoked  = "revoked"
	InvitationStatusExpired  = "expired"
)

type Invitation struct {
	id                string
	appID             string
	email             string
	roleIDs           []string
	invitedBy         string
	codeHash          string
	expiresAt         time.Time
	acceptedAt        *time.Time
	acceptedAccountID *string
	status            string
	createdAt         time.Time
}

func NewInvitation(appID, email string, roleIDs []string, invitedBy, codeHash string, expiresAt time.Time) *Invitation {
	return &Invitation{
		appID:     appID,
		email:     email,
		roleIDs:   roleIDs,
		invitedBy: invitedBy,
		codeHash:  codeHash,
		expiresAt: expiresAt,
		status:    InvitationStatusPending,
	}
}

func NewInvitationFromDO(do *model.Invitation) *Invitation {
	return &Invitation{
		id:                do.Id,
		appID:             do.AppID,
		email:             do.Email,
		roleIDs:           jsonStrings(do.RoleIDs),
		invitedBy:         do.InvitedBy,
		codeHash:          do.CodeHash,
		expiresAt:         do.ExpiresAt,
		acceptedAt:        do.AcceptedAt,
		acceptedAccountID: do.AcceptedAccountID,
		status:            do.Status,
		createdAt:         do.CreatedAt,
	}
}

func (i *Invitation) ToDO() *model.Invitation {
	return &model.Invitation{
		BasePostgres:      vgorm.BasePostgres{Id: i.id},
		AppID:             i.appID,
		Email:             i.email,
		RoleIDs:           stringsJSON(i.roleIDs),
		InvitedBy:         i.invitedBy,
		CodeHash:          i.codeHash,
		ExpiresAt:         i.expiresAt,
		AcceptedAt:        i.acceptedAt,
		AcceptedAccountID: i.acceptedAccountID,
		Status:            i.status,
	}
}

// HasExpired reports whether the invitation is past its expiry time (status
// itself is only flipped lazily by Expire()).
func (i *Invitation) HasExpired(now time.Time) bool {
	return now.After(i.expiresAt)
}

// Accept transitions pending -> accepted, recording the accepting account.
func (i *Invitation) Accept(accountID string, at time.Time) error {
	if i.status != InvitationStatusPending {
		return verrors.ConflictError(fmt.Sprintf("invitation %s not pending (current: %s)", i.id, i.status))
	}
	i.status = InvitationStatusAccepted
	i.acceptedAt = &at
	i.acceptedAccountID = &accountID
	return nil
}

// Revoke transitions pending -> revoked (admin action).
func (i *Invitation) Revoke() error {
	if i.status != InvitationStatusPending {
		return verrors.ConflictError(fmt.Sprintf("invitation %s not pending (current: %s)", i.id, i.status))
	}
	i.status = InvitationStatusRevoked
	return nil
}

// Expire transitions pending -> expired (lazy expiry on read/redeem).
func (i *Invitation) Expire() error {
	if i.status != InvitationStatusPending {
		return verrors.ConflictError(fmt.Sprintf("invitation %s not pending (current: %s)", i.id, i.status))
	}
	i.status = InvitationStatusExpired
	return nil
}

func (i *Invitation) ID() string                { return i.id }
func (i *Invitation) AppID() string             { return i.appID }
func (i *Invitation) Email() string             { return i.email }
func (i *Invitation) RoleIDs() []string         { return i.roleIDs }
func (i *Invitation) InvitedBy() string         { return i.invitedBy }
func (i *Invitation) CodeHash() string          { return i.codeHash }
func (i *Invitation) ExpiresAt() time.Time      { return i.expiresAt }
func (i *Invitation) AcceptedAt() *time.Time    { return i.acceptedAt }
func (i *Invitation) AcceptedAccountID() *string { return i.acceptedAccountID }
func (i *Invitation) Status() string            { return i.status }
func (i *Invitation) CreatedAt() time.Time      { return i.createdAt }

func (i *Invitation) SetCodeHash(v string) { i.codeHash = v }
func (i *Invitation) SetExpiresAt(v time.Time) { i.expiresAt = v }
