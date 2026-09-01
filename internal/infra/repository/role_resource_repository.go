package repository

import (
	"context"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// RoleResourceWithResource is a role_resource row joined with the display
// fields of its resource (aliased to avoid column-name collisions between the
// two tables).
type RoleResourceWithResource struct {
	// embedded: the query selects role_resources.* flat, so GORM must scan
	// these columns inline instead of treating the struct as an association.
	RoleResource   model.RoleResource `gorm:"embedded"`
	ResourceCode   string             `gorm:"column:resource_code"`
	ResourceName   string             `gorm:"column:resource_name"`
	ResourceType   string             `gorm:"column:resource_type"`
	ResourceStatus string             `gorm:"column:resource_status"`
}

// RoleResourceItem is one (resource, effect) attachment to persist: effect
// is allow|deny (M6 deny enablement; "" defaults to allow).
type RoleResourceItem struct {
	ResourceID string
	Effect     string
}

// RoleResourceRepo manages the role -> resource attachment table.
type RoleResourceRepo interface {
	// ReplaceForRole atomically re-grants a role's resource set: soft-deletes
	// the role's existing rows, then inserts items.
	ReplaceForRole(ctx context.Context, roleID string, items []RoleResourceItem) error
	ListByRole(ctx context.Context, roleID string) ([]*model.RoleResource, error)
	// ListByRoleWithResources returns the role's attachments joined with their
	// resource rows.
	ListByRoleWithResources(ctx context.Context, roleID string) ([]RoleResourceWithResource, error)
	// ListByResource returns the attachments pointing at one resource (used
	// to clean up in-memory policies when a resource is deleted/disabled).
	ListByResource(ctx context.Context, resourceID string) ([]*model.RoleResource, error)
	// ListPolicyRows returns the full role_resources join used by the Casbin
	// loader. Rows referencing soft-deleted/disabled roles, resources or apps
	// are excluded by the query itself.
	ListPolicyRows(ctx context.Context) ([]PolicyRoleResource, error)
}

type roleResourceRepoImpl struct {
	db *gorm.DB
}

func NewRoleResourceRepo(db *gorm.DB) RoleResourceRepo {
	return &roleResourceRepoImpl{db: db}
}

// ReplaceForRole runs delete-then-insert in one transaction. Input resource
// ids are deduplicated to respect the (role_id, resource_id) unique index
// (the first occurrence of an id wins, including its effect).
func (r *roleResourceRepoImpl) ReplaceForRole(ctx context.Context, roleID string, items []RoleResourceItem) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("role_id = ?", roleID).Delete(&model.RoleResource{}).Error; err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		seen := make(map[string]struct{}, len(items))
		rows := make([]model.RoleResource, 0, len(items))
		for _, item := range items {
			if _, dup := seen[item.ResourceID]; dup {
				continue
			}
			seen[item.ResourceID] = struct{}{}
			effect := item.Effect
			if effect != "allow" && effect != "deny" {
				effect = grantEffectAllow
			}
			rows = append(rows, model.RoleResource{RoleID: roleID, ResourceID: item.ResourceID, Effect: effect})
		}
		return tx.Create(&rows).Error
	})
}

func (r *roleResourceRepoImpl) ListByRole(ctx context.Context, roleID string) ([]*model.RoleResource, error) {
	var out []*model.RoleResource
	err := r.db.WithContext(ctx).
		Where("role_id = ?", roleID).
		Order("created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *roleResourceRepoImpl) ListByRoleWithResources(ctx context.Context, roleID string) ([]RoleResourceWithResource, error) {
	var out []RoleResourceWithResource
	err := r.db.WithContext(ctx).
		Table("role_resources").
		Select("role_resources.*, resources.code AS resource_code, resources.name AS resource_name, "+
			"resources.type AS resource_type, resources.status AS resource_status").
		Joins("JOIN resources ON resources.id = role_resources.resource_id AND resources.deleted_at IS NULL").
		Where("role_resources.role_id = ? AND role_resources.deleted_at IS NULL", roleID).
		Order("role_resources.created_at ASC").
		Scan(&out).Error
	return out, err
}

// ListPolicyRows joins role_resources -> roles -> resources -> apps (the
// resource's app provides the policy dom). Soft-deleted rows and rows whose
// role, resource or app is deleted/disabled are excluded.
func (r *roleResourceRepoImpl) ListPolicyRows(ctx context.Context) ([]PolicyRoleResource, error) {
	var out []PolicyRoleResource
	err := r.db.WithContext(ctx).
		Table("role_resources").
		Select("role_resources.id, roles.id AS role_id, roles.code AS role_code, roles.scope AS role_scope, " +
			"roles.built_in AS role_built_in, roles.app_id AS role_app_id, resources.code AS resource_code, " +
			"resources.app_id AS resource_app_id, apps.key AS resource_app_key, role_resources.effect").
		Joins("JOIN roles ON roles.id = role_resources.role_id AND roles.deleted_at IS NULL").
		Joins("JOIN resources ON resources.id = role_resources.resource_id AND resources.deleted_at IS NULL AND resources.status = 'active'").
		Joins("JOIN apps ON apps.id = resources.app_id AND apps.deleted_at IS NULL AND apps.status = 'active'").
		Where("role_resources.deleted_at IS NULL").
		Scan(&out).Error
	return out, err
}

// ListByResource returns the attachments of one resource.
func (r *roleResourceRepoImpl) ListByResource(ctx context.Context, resourceID string) ([]*model.RoleResource, error) {
	var out []*model.RoleResource
	err := r.db.WithContext(ctx).
		Where("resource_id = ?", resourceID).
		Find(&out).Error
	return out, err
}
