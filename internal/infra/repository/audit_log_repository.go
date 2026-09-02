package repository

import (
	"context"
	"strings"
	"time"

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

// AuditActionCount is one (action, count) group of the summary window.
type AuditActionCount struct {
	Action string `gorm:"column:action"`
	Count  int64  `gorm:"column:count"`
}

// AuditDailyCount is one day bucket ("YYYY-MM-DD") of the summary window.
type AuditDailyCount struct {
	Date  string `gorm:"column:date"`
	Count int64  `gorm:"column:count"`
}

// AuditActorCount is one (actor_type, actor_id) group of the summary window.
type AuditActorCount struct {
	ActorType string `gorm:"column:actor_type"`
	ActorID   string `gorm:"column:actor_id"`
	Count     int64  `gorm:"column:count"`
}

// AuditSummary holds the GROUP BY results over a time window.
type AuditSummary struct {
	ByAction  []AuditActionCount
	Daily     []AuditDailyCount
	TopActors []AuditActorCount
}

// AuditLogRepo appends and queries audit trails (append-only; no updates).
type AuditLogRepo interface {
	Create(ctx context.Context, log *model.AuditLog) error
	// List returns matching logs ordered by created_at DESC with offset
	// pagination; limit is clamped to [1, 200] (<=0 -> default 50).
	List(ctx context.Context, filter AuditLogFilter, limit, offset int) ([]*model.AuditLog, error)
	// Count returns the number of logs matching the filter (admin pagination).
	Count(ctx context.Context, filter AuditLogFilter) (int64, error)
	// Summary aggregates the logs created since `since`, optionally scoped to
	// one org (orgID nil = all orgs); day buckets are formatted as
	// "YYYY-MM-DD" strings and the actor list is capped to the top five.
	Summary(ctx context.Context, since time.Time, orgID *string) (*AuditSummary, error)
	// PurgeBefore hard-deletes rows older than the cutoff (retention janitor).
	PurgeBefore(ctx context.Context, before time.Time) (int64, error)
}

type auditLogRepoImpl struct {
	db *gorm.DB
}

func NewAuditLogRepo(db *gorm.DB) AuditLogRepo {
	return &auditLogRepoImpl{db: db}
}

// dayExpr renders a created_at day bucket per dialect: sqlite has no
// to_char, Postgres has no strftime.
func (r *auditLogRepoImpl) dayExpr() string {
	switch r.db.Dialector.Name() {
	case "sqlite":
		return "strftime('%Y-%m-%d', created_at)"
	default:
		return "to_char(created_at, 'YYYY-MM-DD')"
	}
}

// PurgeBefore deletes audit rows strictly older than the cutoff (hard
// delete: the retention janitor owns the table's lifetime; soft-deleted rows
// would defeat the purpose). Returns the number of rows removed.
func (r *auditLogRepoImpl) PurgeBefore(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("created_at < ?", before).
		Delete(&model.AuditLog{})
	return res.RowsAffected, res.Error
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

func (r *auditLogRepoImpl) Count(ctx context.Context, filter AuditLogFilter) (int64, error) {
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
	var total int64
	err := q.Count(&total).Error
	return total, err
}

// Summary aggregates the window's logs. Three grouped scans (action / day /
// actor) keep each query trivially indexable. When orgID is non-nil the
// window is scoped to that org.
func (r *auditLogRepoImpl) Summary(ctx context.Context, since time.Time, orgID *string) (*AuditSummary, error) {
	out := &AuditSummary{}
	orgFilter := func(q *gorm.DB) *gorm.DB {
		if orgID != nil && *orgID != "" {
			return q.Where("org_id = ?", *orgID)
		}
		return q
	}
	if err := orgFilter(r.db.WithContext(ctx).
		Model(&model.AuditLog{})).
		Select("action, COUNT(*) AS count").
		Where("created_at >= ?", since).
		Group("action").
		Order("count DESC").
		Scan(&out.ByAction).Error; err != nil {
		return nil, err
	}
	dayExpr := r.dayExpr()
	if err := orgFilter(r.db.WithContext(ctx).
		Model(&model.AuditLog{})).
		Select(dayExpr+" AS date, COUNT(*) AS count").
		Where("created_at >= ?", since).
		Group("date").
		Order("date ASC").
		Scan(&out.Daily).Error; err != nil {
		return nil, err
	}
	if err := orgFilter(r.db.WithContext(ctx).
		Model(&model.AuditLog{})).
		// CAST form works on both sqlite (tests) and postgres.
		Select("actor_type, COALESCE(CAST(actor_id AS TEXT), '') AS actor_id, COUNT(*) AS count").
		Where("created_at >= ?", since).
		Group("actor_type, actor_id").
		Order("count DESC").
		Limit(5).
		Scan(&out.TopActors).Error; err != nil {
		return nil, err
	}
	return out, nil
}
