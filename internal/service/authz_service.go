package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/container"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
)

// authzCacheTTL bounds the per-check result cache; RBAC mutations bump the
// policy version, which changes the cache key and invalidates naturally.
const authzCacheTTL = 60 * time.Second

// authzCacheKeyPrefix namespaces the authz/check result cache.
const authzCacheKeyPrefix = "authz:"

// AuthzService is the central PDP endpoint used by business apps.
type AuthzService interface {
	Check(ctx context.Context, req *dto.AuthzCheckReq, actx *AuthContextInfo) (*dto.AuthzCheckResp, error)
}

type authzServiceImpl struct {
	c container.Container
}

// NewAuthzService builds the authz service.
func NewAuthzService(c container.Container) AuthzService {
	return &authzServiceImpl{c: c}
}

func (s *authzServiceImpl) Check(ctx context.Context, req *dto.AuthzCheckReq, actx *AuthContextInfo) (*dto.AuthzCheckResp, error) {
	// Resolve the app and the casbin subject deterministically. M4: client
	// (client_credentials) tokens check their own app with the
	// "client:{id}" subject (the loader grants them their own app wildcard).
	var appKey, subject string
	switch {
	case actx.Kind == "client":
		if strings.TrimSpace(req.Obj) == "" {
			return nil, verrors.BadRequestError("obj is required for client tokens")
		}
		appKey = actx.Aud
		if req.App != "" && req.App != appKey {
			return nil, verrors.ForbiddenError("app does not match the token audience")
		}
		subject = casbinSubjectClient(actx.UserID)
	case actx.Kind == "account":
		appKey = actx.Aud
		if req.App != "" && req.App != appKey {
			return nil, verrors.ForbiddenError("app does not match the token audience")
		}
		subject = casbinSubjectAccount(actx.AccountID)
	default:
		if strings.TrimSpace(req.App) == "" {
			return nil, verrors.BadRequestError("app is required for identity tokens")
		}
		if strings.TrimSpace(req.AccountID) == "" {
			return nil, verrors.BadRequestError("account_id is required for identity tokens")
		}
		appKey = req.App
		subject = casbinSubjectAccount(req.AccountID)
	}

	app, err := s.c.AppRepo().FindByKey(ctx, appKey)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("app not found")
		}
		return nil, verrors.Wrap(err, "find app")
	}

	if actx.Kind == "identity" {
		account, err := s.c.AccountRepo().FindByID(ctx, req.AccountID)
		if err != nil {
			if repository.IsNotFound(err) {
				return nil, verrors.NotFoundError("account not found")
			}
			return nil, verrors.Wrap(err, "find account")
		}
		if account.IdentityID != actx.UserID {
			return nil, verrors.ForbiddenError("account does not belong to the caller")
		}
		if account.AppID != app.Id {
			return nil, verrors.ForbiddenError("account does not belong to this app")
		}
	}

	// Resolve the object: explicit code or (method, path) reverse lookup.
	obj := strings.TrimSpace(req.Obj)
	if obj == "" {
		if strings.TrimSpace(req.Method) == "" || strings.TrimSpace(req.Path) == "" {
			return nil, verrors.BadRequestError("obj or method+path is required")
		}
		resource, err := s.c.ResourceRepo().FindByAppAndRoute(ctx, app.Id, req.Method, req.Path)
		if err != nil {
			if repository.IsNotFound(err) {
				return s.answer(ctx, appKey, subject, obj, "*", false)
			}
			return nil, verrors.Wrap(err, "find resource by route")
		}
		obj = resource.Code
	}
	act := strings.TrimSpace(req.Act)
	if act == "" {
		act = "*"
	}

	// Fail-close: an enforcer error is surfaced as 1500, never an allow.
	allowed, err := s.c.Enforcer().Enforce(subject, appKey, obj, act)
	if err != nil {
		return nil, err
	}
	return s.answer(ctx, appKey, subject, obj, act, allowed)
}

// answer assembles the response through the result cache.
func (s *authzServiceImpl) answer(ctx context.Context, appKey, accountID, obj, act string, allowed bool) (*dto.AuthzCheckResp, error) {
	version, err := casbinx.GetPolicyVersion(ctx, s.c.KV(), appKey)
	if err != nil {
		return nil, verrors.Wrap(err, "read policy version")
	}
	key := fmt.Sprintf("%s%s:%s:%s:%s:%d", authzCacheKeyPrefix, appKey, accountID, obj, act, version)
	if cached, err := s.c.KV().Get(ctx, key); err == nil {
		return &dto.AuthzCheckResp{Allowed: cached == "1", Version: version}, nil
	} else if err != kv.ErrNotFound {
		return nil, verrors.Wrap(err, "read authz cache")
	}
	value := "0"
	if allowed {
		value = "1"
	}
	if obj != "" {
		if err := s.c.KV().Set(ctx, key, value, authzCacheTTL); err != nil {
			return nil, verrors.Wrap(err, "write authz cache")
		}
	}
	return &dto.AuthzCheckResp{Allowed: allowed, Version: version}, nil
}
