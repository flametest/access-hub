package domain

import (
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
)

// Org status values (orgs.status).
const (
	OrgStatusActive   = "active"
	OrgStatusDisabled = "disabled"
)

// OrgMember role values (org_members.org_role). Governance-only: owner/admin
// manage the org itself; "member" has no admin rights on the org.
const (
	OrgRoleOwner  = "owner"
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"
)

type Org struct {
	id        string
	key       string
	name      string
	status    string
	createdAt time.Time
}

func NewOrg(key, name string) *Org {
	return &Org{key: key, name: name, status: OrgStatusActive}
}

func NewOrgFromDO(do *model.Org) *Org {
	return &Org{id: do.Id, key: do.Key, name: do.Name, status: do.Status, createdAt: do.CreatedAt}
}

func (o *Org) ToDO() *model.Org {
	return &model.Org{
		BasePostgres: vgorm.BasePostgres{Id: o.id},
		Key:          o.key,
		Name:         o.name,
		Status:       o.status,
	}
}

// Disable transitions active -> disabled.
func (o *Org) Disable() error {
	if o.status != OrgStatusActive {
		return verrors.ConflictError(fmt.Sprintf("org %s not active (current: %s)", o.id, o.status))
	}
	o.status = OrgStatusDisabled
	return nil
}

// Enable transitions disabled -> active.
func (o *Org) Enable() error {
	if o.status != OrgStatusDisabled {
		return verrors.ConflictError(fmt.Sprintf("org %s not disabled (current: %s)", o.id, o.status))
	}
	o.status = OrgStatusActive
	return nil
}

func (o *Org) ID() string       { return o.id }
func (o *Org) Key() string      { return o.key }
func (o *Org) Name() string     { return o.name }
func (o *Org) Status() string   { return o.status }
func (o *Org) CreatedAt() time.Time { return o.createdAt }

func (o *Org) SetKey(v string)  { o.key = v }
func (o *Org) SetName(v string) { o.name = v }
