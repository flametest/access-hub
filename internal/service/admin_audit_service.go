package service

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
)

// AdminAuditService serves the audit trail with org row-level scoping.
type AdminAuditService interface {
	List(ctx context.Context, actor *AdminActor, action, orgKey string, page, pageSize int) (*dto.AuditLogPage, error)
	// Summary aggregates the trailing window (M6). Platform callers see
	// everything; org admins only their governed orgs.
	Summary(ctx context.Context, actor *AdminActor, days int) (*dto.AuditSummaryResp, error)
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

// summaryDaysBounds clamp the requested window to 1..90 days.
const (
	summaryMinDays = 1
	summaryMaxDays = 90
)

// Summary implements GET /api/v1/admin/audit-logs/summary?days=7. The days
// parameter is clamped to [1, 90]. The GROUP BY aggregates run repo-side;
// non-platform callers are scoped per governed org and the partial results
// are merged (same strategy as List).
func (s *adminAuditServiceImpl) Summary(ctx context.Context, actor *AdminActor, days int) (*dto.AuditSummaryResp, error) {
	if days < summaryMinDays {
		days = 7
	}
	if days > summaryMaxDays {
		days = summaryMaxDays
	}
	since := time.Now().AddDate(0, 0, -days)
	resp := &dto.AuditSummaryResp{
		Days:      days,
		ByAction:  []dto.AuditActionCount{},
		Daily:     []dto.AuditDailyCount{},
		TopActors: []dto.AuditActorCount{},
	}

	merge := func(sum *repository.AuditSummary) {
		resp.ByAction = mergeActionCounts(resp.ByAction, sum.ByAction)
		resp.Daily = mergeDailyCounts(resp.Daily, sum.Daily)
		resp.TopActors = mergeActorCounts(resp.TopActors, sum.TopActors)
	}

	if actor.Platform {
		sum, err := s.c.AuditLogRepo().Summary(ctx, since, nil)
		if err != nil {
			return nil, verrors.Wrap(err, "summarize audit logs")
		}
		merge(sum)
		return resp, nil
	}
	if len(actor.OrgIDs) == 0 {
		return resp, nil
	}
	for _, orgID := range actor.OrgIDs {
		id := orgID
		sum, err := s.c.AuditLogRepo().Summary(ctx, since, &id)
		if err != nil {
			return nil, verrors.Wrap(err, "summarize audit logs")
		}
		merge(sum)
	}
	resp.TopActors = topActors(resp.TopActors, 5)
	return resp, nil
}

func mergeActionCounts(dst []dto.AuditActionCount, src []repository.AuditActionCount) []dto.AuditActionCount {
	for _, s := range src {
		found := false
		for i := range dst {
			if dst[i].Action == s.Action {
				dst[i].Count += s.Count
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, dto.AuditActionCount{Action: s.Action, Count: s.Count})
		}
	}
	sortByCountThenAction(dst, func(i int) (string, int64) { return dst[i].Action, dst[i].Count })
	return dst
}

func mergeDailyCounts(dst []dto.AuditDailyCount, src []repository.AuditDailyCount) []dto.AuditDailyCount {
	for _, s := range src {
		found := false
		for i := range dst {
			if dst[i].Date == s.Date {
				dst[i].Count += s.Count
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, dto.AuditDailyCount{Date: s.Date, Count: s.Count})
		}
	}
	sort.Slice(dst, func(i, j int) bool { return dst[i].Date < dst[j].Date })
	return dst
}

func mergeActorCounts(dst []dto.AuditActorCount, src []repository.AuditActorCount) []dto.AuditActorCount {
	for _, s := range src {
		found := false
		for i := range dst {
			if dst[i].ActorType == s.ActorType && dst[i].ActorID == s.ActorID {
				dst[i].Count += s.Count
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, dto.AuditActorCount{ActorType: s.ActorType, ActorID: s.ActorID, Count: s.Count})
		}
	}
	return dst
}

// sortByCountThenAction orders descending by count, action ascending as
// tiebreak.
func sortByCountThenAction[T any](items []T, key func(i int) (string, int64)) {
	sort.SliceStable(items, func(i, j int) bool {
		actionI, countI := key(i)
		actionJ, countJ := key(j)
		if countI != countJ {
			return countI > countJ
		}
		return actionI < actionJ
	})
}

// topActors trims the merged actor list to the top n by count.
func topActors(items []dto.AuditActorCount, n int) []dto.AuditActorCount {
	sortByCountThenAction(items, func(i int) (string, int64) { return items[i].ActorType + "\x00" + items[i].ActorID, items[i].Count })
	if len(items) > n {
		items = items[:n]
	}
	return items
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
