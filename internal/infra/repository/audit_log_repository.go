package repository

import (
	"context"
	"strings"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

const (
	defaultAuditListLimit = 50
	maxAuditListLimit     = 200
)

// AuditLogFilter narrows List by action, org and actor. All fields optional.
type AuditLogFilter struct {
	Action  *string
	OrgID   *string
	ActorID *string
}

// AuditLogRepo appends and queries audit trails (append-only; no updates).
type AuditLogRepo interface {
	Create(ctx context.Context, log *model.AuditLog) error
	// List returns matching logs ordered by created_at DESC with offset
	// pagination; limit is clamped to [1, 200] (<=0 -> default 50).
	List(ctx context.Context, filter AuditLogFilter, limit, offset int) ([]*model.AuditLog, error)
}

type auditLogRepoImpl struct {
	db *gorm.DB
}

func NewAuditLogRepo(db *gorm.DB) AuditLogRepo {
	return &auditLogRepoImpl{db: db}
}

func (r *auditLogRepoImpl) Create(ctx context.Context, entry *model.AuditLog) error {
	return r.db.WithContext(ctx).Create(entry).Error
}

func (r *auditLogRepoImpl) List(ctx context.Context, filter AuditLogFilter, limit, offset int) ([]*model.AuditLog, error) {
	if limit <= 0 || limit > maxAuditListLimit {
		limit = defaultAuditListLimit
	}
	if offset < 0 {
		offset = 0
	}
	q := r.db.WithContext(ctx).Model(&model.AuditLog{})
	if filter.Action != nil && strings.TrimSpace(*filter.Action) != "" {
		q = q.Where("action = ?", strings.TrimSpace(*filter.Action))
	}
	if filter.OrgID != nil && *filter.OrgID != "" {
		q = q.Where("org_id = ?", *filter.OrgID)
	}
	if filter.ActorID != nil && *filter.ActorID != "" {
		q = q.Where("actor_id = ?", *filter.ActorID)
	}
	var out []*model.AuditLog
	err := q.Order("created_at DESC").Limit(limit).Offset(offset).Find(&out).Error
	return out, err
}
