package service

import (
	"context"
	"fmt"
	"net/url"
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
				// Unknown route: fail-close deny, not cached.
				version, vErr := casbinx.GetPolicyVersion(ctx, s.c.KV(), appKey)
				if vErr != nil {
					return nil, verrors.Wrap(vErr, "read policy version")
				}
				return &dto.AuthzCheckResp{Allowed: false, Version: version}, nil
			}
			return nil, verrors.Wrap(err, "find resource by route")
		}
		obj = resource.Code
	}
	act := strings.TrimSpace(req.Act)
	if act == "" {
		act = "*"
	}

	return s.cachedEnforce(ctx, appKey, subject, obj, act)
}

// cachedEnforce answers the decision through the result cache: a hit skips
// the enforce entirely (the previous order — enforce first, then consult the
// cache — both wasted the evaluation and could return a stale cached answer
// instead of the one just computed). authzCacheTTL is the staleness bound
// for time-dependent ABAC conditions; policy mutations bump the app's policy
// version, which changes the key and invalidates naturally. Key components
// are query-escaped: obj/act/app freely contain ":" (which PathEscape would
// keep, re-creating the collision) and raw concatenation would alias
// distinct tuples onto one entry.
func (s *authzServiceImpl) cachedEnforce(ctx context.Context, appKey, subject, obj, act string) (*dto.AuthzCheckResp, error) {
	version, err := casbinx.GetPolicyVersion(ctx, s.c.KV(), appKey)
	if err != nil {
		return nil, verrors.Wrap(err, "read policy version")
	}
	key := fmt.Sprintf("%s%s:%s:%s:%s:%d", authzCacheKeyPrefix,
		url.QueryEscape(appKey), url.QueryEscape(subject), url.QueryEscape(obj), url.QueryEscape(act), version)
	if cached, err := s.c.KV().Get(ctx, key); err == nil {
		return &dto.AuthzCheckResp{Allowed: cached == "1", Version: version}, nil
	} else if err != kv.ErrNotFound {
		return nil, verrors.Wrap(err, "read authz cache")
	}
	// Fail-close: an enforcer error is surfaced as 1500, never an allow.
	allowed, err := s.c.Enforcer().Enforce(subject, appKey, obj, act)
	if err != nil {
		return nil, err
	}
	value := "0"
	if allowed {
		value = "1"
	}
	if err := s.c.KV().Set(ctx, key, value, authzCacheTTL); err != nil {
		return nil, verrors.Wrap(err, "write authz cache")
	}
	return &dto.AuthzCheckResp{Allowed: allowed, Version: version}, nil
}
