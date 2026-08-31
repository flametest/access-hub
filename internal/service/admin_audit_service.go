package service

import (
	"context"
	"encoding/json"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
)

// AdminAuditService serves the audit trail with org row-level scoping.
type AdminAuditService interface {
	List(ctx context.Context, actor *AdminActor, action, orgKey string, page, pageSize int) (*dto.AuditLogPage, error)
}

type adminAuditServiceImpl struct {
	c container.Container
}

// NewAdminAuditService builds the admin audit service.
func NewAdminAuditService(c container.Container) AdminAuditService {
	return &adminAuditServiceImpl{c: c}
}

func toAuditLogItem(l *model.AuditLog) dto.AuditLogItem {
	item := dto.AuditLogItem{
		ID:        l.Id,
		ActorType: l.ActorType,
		Action:    l.Action,
		CreatedAt: l.CreatedAt,
		Detail:    string(l.Detail),
	}
	if l.ActorID != nil {
		item.ActorID = *l.ActorID
	}
	if l.OrgID != nil {
		item.OrgID = *l.OrgID
	}
	if l.TargetType != nil {
		item.TargetType = *l.TargetType
	}
	if l.TargetID != nil {
		item.TargetID = *l.TargetID
	}
	if l.IP != nil {
		item.IP = *l.IP
	}
	if l.UserAgent != nil {
		item.UserAgent = *l.UserAgent
	}
	return item
}

func (s *adminAuditServiceImpl) List(ctx context.Context, actor *AdminActor, action, orgKey string, page, pageSize int) (*dto.AuditLogPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	// Platform callers see everything; org admins are restricted to the orgs
	// they administer (an explicit org_key must be within their scope).
	if actor.Platform {
		filter := repository.AuditLogFilter{}
		if action != "" {
			filter.Action = &action
		}
		if orgKey != "" {
			org, err := s.c.OrgRepo().FindByKey(ctx, orgKey)
			if err != nil {
				if repository.IsNotFound(err) {
					return nil, verrors.NotFoundError("org not found")
				}
				return nil, verrors.Wrap(err, "find org")
			}
			filter.OrgID = &org.Id
		}
		logs, err := s.c.AuditLogRepo().List(ctx, filter, pageSize, offset)
		if err != nil {
			return nil, verrors.Wrap(err, "list audit logs")
		}
		total, err := s.c.AuditLogRepo().Count(ctx, filter)
		if err != nil {
			return nil, verrors.Wrap(err, "count audit logs")
		}
		return pageOf(logs, total, page, pageSize), nil
	}

	// Non-platform callers: require at least one governed org.
	if len(actor.OrgIDs) == 0 {
		return &dto.AuditLogPage{Items: []dto.AuditLogItem{}, Total: 0, Page: page, PageSize: pageSize}, nil
	}
	if orgKey != "" {
		org, err := s.c.OrgRepo().FindByKey(ctx, orgKey)
		if err != nil {
			if repository.IsNotFound(err) {
				return nil, verrors.NotFoundError("org not found")
			}
			return nil, verrors.Wrap(err, "find org")
		}
		if !containsID(actor.OrgIDs, org.Id) {
			return nil, verrors.ForbiddenError("org outside your scope")
		}
		filter := repository.AuditLogFilter{OrgID: &org.Id}
		if action != "" {
			filter.Action = &action
		}
		logs, err := s.c.AuditLogRepo().List(ctx, filter, pageSize, offset)
		if err != nil {
			return nil, verrors.Wrap(err, "list audit logs")
		}
		total, err := s.c.AuditLogRepo().Count(ctx, filter)
		if err != nil {
			return nil, verrors.Wrap(err, "count audit logs")
		}
		return pageOf(logs, total, page, pageSize), nil
	}

	// No org filter: merge the caller's orgs, newest first.
	var merged []*model.AuditLog
	for _, orgID := range actor.OrgIDs {
		filter := repository.AuditLogFilter{OrgID: &orgID}
		if action != "" {
			filter.Action = &action
		}
		logs, err := s.c.AuditLogRepo().List(ctx, filter, pageSize, 0)
		if err != nil {
			return nil, verrors.Wrap(err, "list audit logs")
		}
		merged = append(merged, logs...)
	}
	sortLogsDesc(merged)
	total := int64(len(merged))
	if offset > len(merged) {
		merged = nil
	} else {
		end := offset + pageSize
		if end > len(merged) {
			end = len(merged)
		}
		merged = merged[offset:end]
	}
	return pageOf(merged, total, page, pageSize), nil
}

func pageOf(logs []*model.AuditLog, total int64, page, pageSize int) *dto.AuditLogPage {
	items := make([]dto.AuditLogItem, 0, len(logs))
	for _, l := range logs {
		items = append(items, toAuditLogItem(l))
	}
	return &dto.AuditLogPage{Items: items, Total: total, Page: page, PageSize: pageSize}
}

// sortLogsDesc orders merged logs newest first (merge path only).
func sortLogsDesc(logs []*model.AuditLog) {
	for i := 1; i < len(logs); i++ {
		for j := i; j > 0 && logs[j].CreatedAt.After(logs[j-1].CreatedAt); j-- {
			logs[j], logs[j-1] = logs[j-1], logs[j]
		}
	}
}

// marshalDetail is a helper for tests/debug of raw detail payloads.
func marshalDetail(m map[string]any) string {
	raw, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(raw)
}
