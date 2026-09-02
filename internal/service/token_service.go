package service

import (
	"context"
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	log "github.com/flametest/vita/vlog"
	"github.com/google/uuid"
)

// kv key namespaces owned by the token service.
const (
	// kvKeyDenyPrefix holds denied (logged out) access-token jti values.
	kvKeyDenyPrefix = "jwt:deny:"
	// kvKeyRetiredPrefix maps a replaced refresh-token hash to its session id
	// so reuse of a rotated token can be detected (design.md §7).
	kvKeyRetiredPrefix = "sess:retired:"
)

// TokenPairResult is the outcome of token issuance.
type TokenPairResult struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
	SessionID    string
}

// TokenService manages refresh-token sessions: creation, in-place rotation
// with reuse detection, revocation and jti denylisting.
type TokenService interface {
	// IdentityPair creates an identity-scope session and issues the portal
	// token pair for the user.
	IdentityPair(ctx context.Context, user *model.User, device, ip string) (*TokenPairResult, error)
	// AccountPair creates an account-scope session and issues the workspace
	// (app) token pair for the account.
	AccountPair(ctx context.Context, account *model.Account, app *model.App, identity *model.User, device, ip string) (*TokenPairResult, error)
	// Rotate verifies the presented refresh token and rotates the session
	// in place. Returns the session and the NEW refresh token. Reuse of an
	// already-rotated token revokes the whole session (and audits it).
	Rotate(ctx context.Context, refreshToken string) (*model.Session, string, error)
	// PairFromSession issues an access token matching the session's scope
	// against the (already rotated) new refresh token.
	PairFromSession(ctx context.Context, session *model.Session, refreshToken string) (*TokenPairResult, error)
	// RevokeSession revokes one session; already-revoked is a no-op.
	RevokeSession(ctx context.Context, id string) error
	// RevokeAllIdentityExcept revokes the identity's identity-scope sessions,
	// keeping the current one signed in.
	RevokeAllIdentityExcept(ctx context.Context, userID, exceptSessionID string) error
	// DenylistJTIDeny denies an access token id until its expiry.
	DenylistJTI(ctx context.Context, jti string, remaining time.Duration) error
	// IsDenied reports whether the jti is denylisted.
	IsDenied(ctx context.Context, jti string) bool
}

type tokenServiceImpl struct {
	c container.Container
}

// NewTokenService builds the token service.
func NewTokenService(c container.Container) TokenService {
	return &tokenServiceImpl{c: c}
}

func (s *tokenServiceImpl) IdentityPair(ctx context.Context, user *model.User, device, ip string) (*TokenPairResult, error) {
	return s.createSession(ctx, &sessionSpec{
		userID:   user.Id,
		scope:    domain.SessionScopeIdentity,
		device:   device,
		ip:       ip,
		identity: user,
	}, nil, nil)
}

func (s *tokenServiceImpl) AccountPair(ctx context.Context, account *model.Account, app *model.App, identity *model.User, device, ip string) (*TokenPairResult, error) {
	return s.createSession(ctx, &sessionSpec{
		userID:   account.IdentityID,
		scope:    domain.SessionScopeAccount,
		device:   device,
		ip:       ip,
		identity: identity,
	}, account, app)
}

// sessionSpec captures the inputs of session creation.
type sessionSpec struct {
	userID   string
	scope    string
	device   string
	ip       string
	identity *model.User
}

func (s *tokenServiceImpl) createSession(ctx context.Context, spec *sessionSpec, account *model.Account, app *model.App) (*TokenPairResult, error) {
	cfg := s.c.Cfg().Auth
	refresh, err := randomToken()
	if err != nil {
		return nil, verrors.InternalServerError(fmt.Sprintf("generate refresh token: %v", err))
	}
	session := &model.Session{
		BasePostgres:     vgorm.BasePostgres{Id: uuid.NewString()},
		UserID:           spec.userID,
		Scope:            spec.scope,
		RefreshTokenHash: sha256Hex(refresh),
		ExpiresAt:        time.Now().Add(cfg.RefreshTokenTTL),
	}
	if spec.device != "" {
		d := spec.device
		session.Device = &d
	}
	if spec.ip != "" {
		v := spec.ip
		session.IP = &v
	}
	if account != nil {
		aid := account.Id
		session.AccountID = &aid
	}
	if app != nil {
		v := app.Id
		session.AppID = &v
	}
	now := time.Now()
	session.LastUsedAt = &now
	if err := s.c.SessionRepo().Create(ctx, session); err != nil {
		return nil, verrors.Wrap(err, "create session")
	}
	return s.issuePair(ctx, session, spec.identity, account, app, refresh, cfg.AccessTokenTTL)
}

// issuePair signs the access token for a freshly created (or rotated)
// session and assembles the token pair.
func (s *tokenServiceImpl) issuePair(
	ctx context.Context,
	session *model.Session,
	identity *model.User,
	account *model.Account,
	app *model.App,
	refreshToken string,
	accessTTL time.Duration,
) (*TokenPairResult, error) {
	var claims *jwt.Claims
	switch session.Scope {
	case domain.SessionScopeIdentity:
		if identity == nil {
			var err error
			identity, err = s.c.UserRepo().FindByID(ctx, session.UserID)
			if err != nil {
				return nil, verrors.Wrap(err, "load session identity")
			}
		}
		claims = jwt.NewIdentityClaims(identity.Id, session.Id, identity.Username, identity.Email, accessTTL)
	case domain.SessionScopeAccount:
		if account == nil {
			var err error
			account, err = s.c.AccountRepo().FindByID(ctx, deref(session.AccountID))
			if err != nil {
				return nil, verrors.Wrap(err, "load session account")
			}
		}
		if app == nil {
			var err error
			app, err = s.c.AppRepo().FindByID(ctx, deref(session.AppID))
			if err != nil {
				return nil, verrors.Wrap(err, "load session app")
			}
		}
		if identity == nil {
			var err error
			identity, err = s.c.UserRepo().FindByID(ctx, account.IdentityID)
			if err != nil {
				return nil, verrors.Wrap(err, "load account identity")
			}
		}
		claims = jwt.NewAccountClaims(account.Id, identity.Id, app.Key, session.Id, identity.Username, identity.Email, accessTTL)
	default:
		return nil, verrors.InternalServerError(fmt.Sprintf("unknown session scope %q", session.Scope))
	}
	signed, err := s.c.JWT().Issue(claims)
	if err != nil {
		return nil, err
	}
	return &TokenPairResult{
		AccessToken:  signed,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTTL.Seconds()),
		SessionID:    session.Id,
	}, nil
}

func (s *tokenServiceImpl) PairFromSession(ctx context.Context, session *model.Session, refreshToken string) (*TokenPairResult, error) {
	return s.issuePair(ctx, session, nil, nil, nil, refreshToken, s.c.Cfg().Auth.AccessTokenTTL)
}

func (s *tokenServiceImpl) Rotate(ctx context.Context, refreshToken string) (*model.Session, string, error) {
	now := time.Now()
	presented := sha256Hex(refreshToken)
	session, err := s.c.SessionRepo().FindByTokenHash(ctx, presented)
	if err != nil {
		if !repository.IsNotFound(err) {
			return nil, "", verrors.Wrap(err, "find session by refresh token")
		}
		// Not the current hash: check the retired-hash index. A hit means the
		// presented token was already rotated away — treat as a leak and
		// revoke the whole session.
		if sid, kvErr := s.c.KV().Get(ctx, kvKeyRetiredPrefix+presented); kvErr == nil && sid != "" {
			_ = s.c.SessionRepo().Revoke(ctx, sid, now)
			writeAudit(ctx, s.c, ActorSystem, "", nil, AuditTokenReuse, "session", sid,
				map[string]any{"reason": "refresh token reuse detected"}, "", "")
			return nil, "", verrors.UnauthorizedError("refresh token reuse detected, session revoked")
		}
		return nil, "", verrors.UnauthorizedError("invalid refresh token")
	}
	if session.RevokedAt != nil {
		return nil, "", verrors.UnauthorizedError("session already revoked")
	}
	if !now.Before(session.ExpiresAt) {
		return nil, "", verrors.UnauthorizedError("session expired")
	}

	newToken, err := randomToken()
	if err != nil {
		return nil, "", verrors.InternalServerError(fmt.Sprintf("generate refresh token: %v", err))
	}
	// Compare-and-swap rotation: two concurrent presentations of the same
	// (current) token must not both succeed — the loser detects the CAS miss
	// as reuse and revokes the session.
	rotated, err := s.c.SessionRepo().RotateToken(ctx, session.Id, presented, sha256Hex(newToken), now)
	if err != nil {
		return nil, "", verrors.Wrap(err, "rotate session")
	}
	if !rotated {
		_ = s.c.SessionRepo().Revoke(ctx, session.Id, now)
		writeAudit(ctx, s.c, ActorSystem, "", nil, AuditTokenReuse, "session", session.Id,
			map[string]any{"reason": "concurrent refresh token rotation detected"}, "", "")
		return nil, "", verrors.UnauthorizedError("refresh token reuse detected, session revoked")
	}
	// Retire the presented hash so a later replay is detected within the
	// refresh TTL window. Best-effort: the CAS above is the primary guard,
	// a failed write only weakens replay detection until the TTL passes.
	if err := s.c.KV().Set(ctx, kvKeyRetiredPrefix+presented, session.Id, s.c.Cfg().Auth.RefreshTokenTTL); err != nil {
		log.Warn().Any("error", err).Msg("record retired refresh token failed (replay detection degraded)")
	}
	session.RefreshTokenHash = sha256Hex(newToken)
	session.RotationCount++
	session.LastUsedAt = &now
	return session, newToken, nil
}

func (s *tokenServiceImpl) RevokeSession(ctx context.Context, id string) error {
	if err := s.c.SessionRepo().Revoke(ctx, id, time.Now()); err != nil {
		// Already revoked / missing: logout stays idempotent.
		var vErr *verrors.Error
		if verrors.As(err, &vErr) && vErr.ErrCode() == verrors.ConflictCode {
			return nil
		}
		if repository.IsNotFound(err) {
			return nil
		}
		return verrors.Wrap(err, "revoke session")
	}
	return nil
}

func (s *tokenServiceImpl) RevokeAllIdentityExcept(ctx context.Context, userID, exceptSessionID string) error {
	if err := s.c.SessionRepo().RevokeAllForUserByScopeExcept(ctx, userID, domain.SessionScopeIdentity, exceptSessionID, time.Now()); err != nil {
		return verrors.Wrap(err, "revoke identity sessions")
	}
	return nil
}

func (s *tokenServiceImpl) DenylistJTI(ctx context.Context, jti string, remaining time.Duration) error {
	if jti == "" {
		return nil
	}
	if remaining <= 0 {
		remaining = time.Second
	}
	if err := s.c.KV().Set(ctx, kvKeyDenyPrefix+jti, "1", remaining); err != nil {
		return verrors.Wrap(err, "denylist token")
	}
	return nil
}

func (s *tokenServiceImpl) IsDenied(ctx context.Context, jti string) bool {
	_, err := s.c.KV().Get(ctx, kvKeyDenyPrefix+jti)
	return err == nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
