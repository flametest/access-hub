package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/internal/infra/social"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	log "github.com/flametest/vita/vlog"
	"github.com/google/uuid"
)

// kv namespaces and TTLs for the social login one-time tokens
// (design.md §12 M5: tokens never travel through URLs — the callback only
// hands out a one-time login_code).
const (
	kvSocialStatePrefix = "social:state:"
	kvSocialLoginPrefix = "social:login:"
	socialStateTTL      = 10 * time.Minute
	socialLoginCodeTTL  = 5 * time.Minute

	// SocialModeLogin / SocialModeLink are the two start modes.
	SocialModeLogin = "login"
	SocialModeLink  = "link"

	// socialDefaultRedirect is the portal landing page used when a login-mode
	// start request does not carry a redirect path.
	socialDefaultRedirect = "/workspaces"
	// socialCompletePath is the portal page that consumes the login_code
	// (and the fixed landing page of a successful link).
	socialCompletePath = "/social/complete"
)

// Portal error codes surfaced as ?error={code} redirects.
const (
	socialErrInvalidState    = "invalid_state"
	socialErrProviderError   = "provider_error"
	socialErrNotRegistered   = "not_registered"
	socialErrAccountDisabled = "account_disabled"
	socialErrAlreadyLinked   = "already_linked"
)

// socialState is the payload stored server-side behind the opaque state
// parameter (kv, 10 min TTL, consumed once).
type socialState struct {
	Provider string `json:"provider"`
	Redirect string `json:"redirect"`
	Mode     string `json:"mode"` // login | link
	UserID   string `json:"user_id,omitempty"`
	Nonce    string `json:"nonce"`
}

// socialLoginCode is the payload behind the one-time login_code.
type socialLoginCode struct {
	UserID string `json:"user_id"`
}

// Sentinel resolution errors mapped onto portal error redirects.
var (
	errSocialAccountDisabled = errors.New("social: account disabled")
	errSocialNotRegistered   = errors.New("social: not registered")
)

// SocialCallbackResult tells the handler how to answer the browser: a 302
// redirect for GET callbacks, or a minimal self-replacing HTML page for
// form_post (Apple) callbacks — a POST response cannot redirect.
type SocialCallbackResult struct {
	RedirectURL string
	HTML        string
}

// SocialService implements the social login flow:
// start -> provider -> callback -> (identity resolution) -> one-time
// login_code -> POST /auth/social/complete -> tokens (or the 2FA challenge).
type SocialService interface {
	// Start builds the provider authorization URL. mode=link binds the new
	// provider identity to the caller (identity token required).
	Start(ctx context.Context, providerID, redirect, mode string, actx *AuthContextInfo) (string, error)
	// Callback consumes the one-time state, resolves the profile and returns
	// the browser outcome. form is non-nil for POST (form_post) callbacks.
	Callback(ctx context.Context, providerID, code, state string, form social.Form) (*SocialCallbackResult, error)
	// ProviderFailure builds the browser outcome for a provider-side error
	// (the provider redirected back with ?error=..., e.g. the user denied
	// consent): it consumes the one-time state when present and answers with
	// the portal error page (reason provider_error).
	ProviderFailure(ctx context.Context, providerID, state string, form social.Form) (*SocialCallbackResult, error)
	// Complete exchanges a one-time login_code for tokens (or the 2FA
	// login challenge) plus the pending invitations for the user's email.
	Complete(ctx context.Context, loginCode, device, ip string) (*dto.SocialCompleteResp, error)
	// ListIdentities lists the caller's social bindings.
	ListIdentities(ctx context.Context, userID string) ([]dto.SocialIdentityItem, error)
	// RemoveIdentity unlinks one social binding (with the last-method guard).
	RemoveIdentity(ctx context.Context, userID, identityID string) error
}

type socialServiceImpl struct {
	c     container.Container
	token TokenService
}

// NewSocialService builds the social login service.
func NewSocialService(c container.Container) SocialService {
	return &socialServiceImpl{c: c, token: NewTokenService(c)}
}

// ---------- start ----------

func (s *socialServiceImpl) Start(ctx context.Context, providerID, redirect, mode string, actx *AuthContextInfo) (string, error) {
	p := s.provider(providerID)
	if p == nil || !p.Enabled() {
		return "", verrors.NotFoundError("social provider not available")
	}
	if mode == "" {
		mode = SocialModeLogin
	}
	if mode != SocialModeLogin && mode != SocialModeLink {
		return "", verrors.BadRequestError("mode must be login or link")
	}
	state := &socialState{Provider: providerID, Mode: mode}
	switch mode {
	case SocialModeLink:
		if actx == nil || actx.Kind != "identity" {
			return "", verrors.UnauthorizedError("authentication required to link a social identity")
		}
		state.UserID = actx.UserID
	default:
		state.Redirect = sanitizeRedirect(redirect, socialDefaultRedirect)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return "", verrors.InternalServerError(fmt.Sprintf("marshal social state: %v", err))
	}
	stateToken, err := randomHex(16) // 32 hex chars
	if err != nil {
		return "", verrors.InternalServerError(fmt.Sprintf("generate social state: %v", err))
	}
	if err := s.c.KV().Set(ctx, kvSocialStatePrefix+stateToken, string(raw), socialStateTTL); err != nil {
		return "", verrors.Wrap(err, "store social state")
	}
	return p.AuthCodeURL(s.callbackURL(providerID), stateToken), nil
}

// ---------- callback ----------

func (s *socialServiceImpl) Callback(ctx context.Context, providerID, code, state string, form social.Form) (*SocialCallbackResult, error) {
	p := s.provider(providerID)
	if p == nil || !p.Enabled() {
		return nil, verrors.NotFoundError("social provider not available")
	}
	// One-time state consumption: replays/expiry land on the portal error page.
	statePayload, err := s.consumeState(ctx, providerID, state)
	if err != nil {
		return s.failResult(nil, form, socialErrInvalidState), nil
	}

	profile, err := s.exchangeProfile(ctx, p, providerID, code, form)
	if err != nil {
		log.Warn().Any("error", err).Any("provider", providerID).Msg("social profile exchange failed")
		return s.failResult(statePayload, form, socialErrProviderError), nil
	}

	var result *SocialCallbackResult
	switch statePayload.Mode {
	case SocialModeLink:
		result, err = s.linkCallback(ctx, statePayload, providerID, profile, form)
	default:
		result, err = s.loginCallback(ctx, statePayload, providerID, profile, form)
	}
	if err != nil {
		if errCode, ok := socialRedirectError(err); ok {
			return s.failResult(statePayload, form, errCode), nil
		}
		return nil, err
	}
	return result, nil
}

// ProviderFailure implements the provider-side error branch of the callback
// (the provider answered ?error=... instead of code+state): the pending
// one-time state (if any) is burned and the browser is sent to the portal
// error page with reason provider_error.
func (s *socialServiceImpl) ProviderFailure(ctx context.Context, providerID, state string, form social.Form) (*SocialCallbackResult, error) {
	p := s.provider(providerID)
	if p == nil || !p.Enabled() {
		return nil, verrors.NotFoundError("social provider not available")
	}
	statePayload, _ := s.consumeState(ctx, providerID, state) // best-effort burn
	log.Warn().Any("provider", providerID).Msg("social callback returned a provider error")
	return s.failResult(statePayload, form, socialErrProviderError), nil
}

// consumeState loads and deletes the one-time state (Get-then-Del; a replay
// finds nothing).
func (s *socialServiceImpl) consumeState(ctx context.Context, providerID, state string) (*socialState, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, kv.ErrNotFound
	}
	raw, err := s.c.KV().Get(ctx, kvSocialStatePrefix+state)
	if err != nil {
		return nil, err
	}
	_ = s.c.KV().Del(ctx, kvSocialStatePrefix+state)
	var payload socialState
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	if payload.Provider != providerID {
		return nil, kv.ErrNotFound
	}
	return &payload, nil
}

// exchangeProfile resolves the provider profile from the callback payload.
func (s *socialServiceImpl) exchangeProfile(ctx context.Context, p social.Provider, providerID, code string, form social.Form) (*social.Profile, error) {
	redirectURI := s.callbackURL(providerID)
	if fx, ok := p.(social.FormExchanger); ok && form != nil {
		return fx.ExchangeForm(ctx, form, redirectURI)
	}
	return p.Exchange(ctx, code, redirectURI)
}

// ---------- login-mode resolution ----------

// loginCallback resolves (or creates) the owning user and hands out the
// one-time login_code. Resolution order (design.md §12 M5):
//  1. identity by (provider, provider_user_id) -> its user;
//  2. verified-email match -> auto-merge (identity row bound to that user);
//  3. AllowAutoRegister -> brand-new user + identity row;
//  4. otherwise -> not_registered error redirect.
func (s *socialServiceImpl) loginCallback(ctx context.Context, state *socialState, providerID string, profile *social.Profile, form social.Form) (*SocialCallbackResult, error) {
	var userID string
	err := runInTx(s.c, func(r *txRepos) error {
		uid, txErr := s.resolveSocialUser(ctx, r, providerID, profile)
		if txErr != nil {
			return txErr
		}
		userID = uid
		return nil
	})
	if err != nil {
		return nil, err
	}
	user, err := s.c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return nil, verrors.Wrap(err, "load social user")
	}
	_ = s.c.UserRepo().TouchLastLogin(ctx, user.Id, time.Now())
	loginCode, err := s.issueLoginCode(ctx, user.Id)
	if err != nil {
		return nil, err
	}
	writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditLoginSuccess, "user", user.Id,
		map[string]any{"via": "social", "provider": providerID}, "", "")
	return s.successResult(state, form, url.Values{"login_code": {loginCode}}), nil
}

// resolveSocialUser runs inside the resolution transaction.
func (s *socialServiceImpl) resolveSocialUser(ctx context.Context, r *txRepos, providerID string, profile *social.Profile) (string, error) {
	// 1. Existing binding wins.
	identity, err := r.identities.FindByProviderAndUID(ctx, providerID, profile.ProviderUserID)
	if err == nil {
		user, uErr := r.users.FindByID(ctx, identity.UserID)
		if uErr != nil {
			return "", uErr
		}
		if user.Status != domain.UserStatusActive {
			return "", errSocialAccountDisabled
		}
		return user.Id, nil
	}
	if !repository.IsNotFound(err) {
		return "", err
	}

	// 2. Verified-email auto-merge keeps the existing identity.
	if profile.EmailVerified && profile.Email != "" {
		user, uErr := r.users.FindByEmail(ctx, profile.Email)
		if uErr != nil && !repository.IsNotFound(uErr) {
			return "", uErr
		}
		if user != nil {
			if user.Status != domain.UserStatusActive {
				return "", errSocialAccountDisabled
			}
			row, cErr := s.createIdentity(ctx, r, user.Id, providerID, profile)
			if cErr != nil {
				return "", cErr
			}
			writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditSocialLinked, "identity", row.Id,
				map[string]any{"provider": providerID, "via": "email_merge"}, "", "")
			return user.Id, nil
		}
	}

	// 3. Auto-registration (requires a verified email).
	if !s.c.Cfg().Auth.AllowAutoRegister || !profile.EmailVerified || profile.Email == "" {
		return "", errSocialNotRegistered
	}
	username, err := uniqueSocialUsername(ctx, r.users)
	if err != nil {
		return "", err
	}
	user := &model.User{
		BasePostgres:  vgorm.BasePostgres{Id: uuid.NewString()},
		Username:      username,
		Email:         normalizeEmail(profile.Email),
		EmailVerified: true,
		Status:        domain.UserStatusActive,
	}
	if profile.DisplayName != "" {
		n := profile.DisplayName
		user.Nickname = &n
	}
	if err := r.users.Create(ctx, user); err != nil {
		return "", err
	}
	if _, err := s.createIdentity(ctx, r, user.Id, providerID, profile); err != nil {
		return "", err
	}
	writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditSocialRegister, "user", user.Id,
		map[string]any{"provider": providerID}, "", "")
	return user.Id, nil
}

// createIdentity stores the (provider, provider_user_id) binding for a user.
func (s *socialServiceImpl) createIdentity(ctx context.Context, r *txRepos, userID, providerID string, profile *social.Profile) (*model.Identity, error) {
	identity := &model.Identity{
		BasePostgres:   vgorm.BasePostgres{Id: uuid.NewString()},
		UserID:         userID,
		Provider:       providerID,
		ProviderUserID: profile.ProviderUserID,
		EmailVerified:  profile.EmailVerified,
	}
	if profile.Email != "" {
		e := normalizeEmail(profile.Email)
		identity.Email = &e
	}
	if profile.DisplayName != "" {
		d := profile.DisplayName
		identity.DisplayName = &d
	}
	if profile.AvatarURL != "" {
		a := profile.AvatarURL
		identity.AvatarURL = &a
	}
	if len(profile.Raw) > 0 {
		if raw, err := json.Marshal(profile.Raw); err == nil {
			identity.RawProfile = raw
		}
	}
	if err := r.identities.Create(ctx, identity); err != nil {
		return nil, verrors.Wrap(err, "create social identity")
	}
	return identity, nil
}

// uniqueSocialUsername derives "u_<rand8>" usernames for social
// auto-registration, retrying until the code is free.
func uniqueSocialUsername(ctx context.Context, users repository.UserRepo) (string, error) {
	for i := 0; i < 20; i++ {
		suffix, err := randomHex(4)
		if err != nil {
			return "", err
		}
		candidate := "u_" + suffix
		if _, err := users.FindByUsername(ctx, candidate); repository.IsNotFound(err) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("derive social username: exhausted retries")
}

// ---------- link-mode resolution ----------

func (s *socialServiceImpl) linkCallback(ctx context.Context, state *socialState, providerID string, profile *social.Profile, form social.Form) (*SocialCallbackResult, error) {
	var result *SocialCallbackResult
	err := runInTx(s.c, func(r *txRepos) error {
		existing, err := r.identities.FindByProviderAndUID(ctx, providerID, profile.ProviderUserID)
		switch {
		case err == nil:
			if existing.UserID == state.UserID {
				// Already bound to the caller: idempotent success.
				result = s.linkDoneResult(form)
				return nil
			}
			result = s.failResult(state, form, socialErrAlreadyLinked)
			return nil
		case !repository.IsNotFound(err):
			return err
		}
		row, err := s.createIdentity(ctx, r, state.UserID, providerID, profile)
		if err != nil {
			return err
		}
		writeAudit(ctx, s.c, ActorIdentity, state.UserID, nil, AuditSocialLinked, "identity", row.Id,
			map[string]any{"provider": providerID}, "", "")
		result = s.linkDoneResult(form)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ---------- complete ----------

// Complete exchanges the one-time login_code for the session: a 2FA challenge
// for identities with a confirmed TOTP enrollment (the M4 login challenge is
// reused as-is), otherwise the standard token pair.
func (s *socialServiceImpl) Complete(ctx context.Context, loginCode, device, ip string) (*dto.SocialCompleteResp, error) {
	code := strings.TrimSpace(loginCode)
	keys := []string{"socialcomplete:ip:" + ip}
	if err := guardCheckLock(ctx, s.c, keys); err != nil {
		return nil, err
	}
	fail := func() error {
		guardRecordFailure(ctx, s.c, keys)
		return verrors.NotFoundError("invalid or expired login code")
	}
	raw, err := s.c.KV().Get(ctx, kvSocialLoginPrefix+code)
	if err != nil {
		if err == kv.ErrNotFound {
			return nil, fail()
		}
		return nil, verrors.Wrap(err, "load login code")
	}
	_ = s.c.KV().Del(ctx, kvSocialLoginPrefix+code) // one-time consumption
	var payload socialLoginCode
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || payload.UserID == "" {
		return nil, fail()
	}
	user, err := s.c.UserRepo().FindByID(ctx, payload.UserID)
	if err != nil {
		return nil, fail()
	}
	if user.Status != domain.UserStatusActive {
		return nil, verrors.ForbiddenError("account disabled")
	}
	guardClearFailures(ctx, s.c, keys)
	_ = s.c.UserRepo().TouchLastLogin(ctx, user.Id, time.Now())

	resp := &dto.SocialCompleteResp{PendingInvitations: s.pendingInvitations(ctx, user.Email)}
	// Same 2FA challenge as the password/email logins (design.md §12 M5 ③).
	if twoFAConfirmed(ctx, s.c, user.Id) {
		mfaToken, err := s.c.JWT().Issue(jwt.NewMFAClaims(user.Id, s.c.Cfg().Auth.MFATokenTTL))
		if err != nil {
			return nil, err
		}
		resp.MfaRequired = true
		resp.MfaToken = mfaToken
		return resp, nil
	}
	pair, err := s.token.IdentityPair(ctx, user, device, ip)
	if err != nil {
		return nil, err
	}
	tp := toTokenPair(pair, device, ip)
	resp.AccessToken = tp.AccessToken
	resp.RefreshToken = tp.RefreshToken
	resp.TokenType = tp.TokenType
	resp.ExpiresIn = tp.ExpiresIn
	resp.Session = tp.Session
	return resp, nil
}

// pendingInvitations lists unexpired pending invitations for the user's
// email. Best-effort: failures yield an empty list.
func (s *socialServiceImpl) pendingInvitations(ctx context.Context, email string) []dto.PendingInvitation {
	out := []dto.PendingInvitation{}
	if email == "" {
		return out
	}
	invitations, err := s.c.InvitationRepo().ListPendingByEmail(ctx, email)
	if err != nil {
		return out
	}
	for _, inv := range invitations {
		app, err := s.c.AppRepo().FindByID(ctx, inv.AppID)
		if err != nil {
			continue
		}
		out = append(out, dto.PendingInvitation{AppKey: app.Key, AppName: app.Name})
	}
	return out
}

// ---------- me: social identities ----------

func (s *socialServiceImpl) ListIdentities(ctx context.Context, userID string) ([]dto.SocialIdentityItem, error) {
	rows, err := s.c.IdentityRepo().ListByUser(ctx, userID)
	if err != nil {
		return nil, verrors.Wrap(err, "list social identities")
	}
	out := make([]dto.SocialIdentityItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, dto.SocialIdentityItem{
			ID:            row.Id,
			Provider:      row.Provider,
			Email:         deref(row.Email),
			EmailVerified: row.EmailVerified,
			DisplayName:   deref(row.DisplayName),
			CreatedAt:     row.CreatedAt,
		})
	}
	return out, nil
}

// RemoveIdentity unlinks one social binding. Guard: the user must retain a
// login path — a set password or at least one remaining social binding.
func (s *socialServiceImpl) RemoveIdentity(ctx context.Context, userID, identityID string) error {
	user, err := s.c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return verrors.NotFoundError("identity not found")
	}
	row, err := s.c.IdentityRepo().FindByID(ctx, identityID)
	if err != nil {
		return verrors.NotFoundError("social identity not found")
	}
	if row.UserID != userID {
		return verrors.NotFoundError("social identity not found")
	}
	count, err := s.c.IdentityRepo().CountByUser(ctx, userID)
	if err != nil {
		return verrors.Wrap(err, "count social identities")
	}
	hasPassword := user.PasswordHash != nil && *user.PasswordHash != ""
	if !hasPassword && count < 2 {
		return verrors.ConflictError("cannot remove the last sign-in method")
	}
	if err := s.c.IdentityRepo().Delete(ctx, identityID); err != nil {
		return err
	}
	writeAudit(ctx, s.c, ActorIdentity, userID, nil, AuditSocialUnlinked, "identity", identityID,
		map[string]any{"provider": row.Provider}, "", "")
	return nil
}

// ---------- helpers ----------

// provider looks up the configured provider (nil when unknown).
func (s *socialServiceImpl) provider(providerID string) social.Provider {
	registry := s.c.SocialRegistry()
	if registry == nil {
		return nil
	}
	return registry[providerID]
}

// callbackURL is the provider-console callback URL for one provider
// ({Auth.IssuerURL}/api/v1/auth/social/{provider}/callback).
func (s *socialServiceImpl) callbackURL(providerID string) string {
	return strings.TrimRight(s.c.Cfg().Auth.IssuerURL, "/") + "/api/v1/auth/social/" + providerID + "/callback"
}

// issueLoginCode mints the one-time login_code consumed by /complete.
func (s *socialServiceImpl) issueLoginCode(ctx context.Context, userID string) (string, error) {
	code, err := randomHex(16) // 32 hex chars
	if err != nil {
		return "", verrors.InternalServerError(fmt.Sprintf("generate login code: %v", err))
	}
	raw, err := json.Marshal(&socialLoginCode{UserID: userID})
	if err != nil {
		return "", verrors.InternalServerError(fmt.Sprintf("marshal login code: %v", err))
	}
	if err := s.c.KV().Set(ctx, kvSocialLoginPrefix+code, string(raw), socialLoginCodeTTL); err != nil {
		return "", verrors.Wrap(err, "store login code")
	}
	return code, nil
}

// sanitizeRedirect validates a portal-relative redirect path: it must start
// with a single "/" (no scheme-relative "//", no backslash tricks).
func sanitizeRedirect(redirect, fallback string) string {
	if redirect == "" {
		return fallback
	}
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") || strings.Contains(redirect, "\\") {
		return fallback
	}
	return redirect
}

// portalTarget composes an absolute portal URL: {PortalURL}{path}?{query}.
func (s *socialServiceImpl) portalTarget(path string, query url.Values) string {
	target := strings.TrimRight(s.c.Cfg().Auth.PortalURL, "/") + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	return target
}

// successResult targets the state redirect (default /social/complete) with
// the given query (login_code / linked).
func (s *socialServiceImpl) successResult(state *socialState, form social.Form, query url.Values) *SocialCallbackResult {
	path := socialCompletePath
	if state != nil {
		path = sanitizeRedirect(state.Redirect, socialCompletePath)
	}
	return s.outcome(s.portalTarget(path, query), form)
}

// linkDoneResult targets the fixed {PortalURL}/social/complete?linked=1.
func (s *socialServiceImpl) linkDoneResult(form social.Form) *SocialCallbackResult {
	return s.outcome(s.portalTarget(socialCompletePath, url.Values{"linked": {"1"}}), form)
}

// failResult targets the portal with an ?error={code} query.
func (s *socialServiceImpl) failResult(state *socialState, form social.Form, errCode string) *SocialCallbackResult {
	path := socialCompletePath
	if state != nil {
		path = sanitizeRedirect(state.Redirect, socialCompletePath)
	}
	return s.outcome(s.portalTarget(path, url.Values{"error": {errCode}}), form)
}

// outcome wraps the portal target: POST (form_post) callbacks must answer
// 200 HTML that location.replace()s to the target — a 302 cannot carry the
// POST context.
func (s *socialServiceImpl) outcome(target string, form social.Form) *SocialCallbackResult {
	res := &SocialCallbackResult{RedirectURL: target}
	if form != nil {
		res.HTML = formPostHTML(target)
	}
	return res
}

// formPostHTML renders the minimal self-replacing page for form_post
// callbacks.
func formPostHTML(target string) string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signing in…</title></head>` +
		`<body><script>location.replace(` + strconv.Quote(target) + `);</script>` +
		`<noscript><a href="` + html.EscapeString(target) + `">Continue</a></noscript></body></html>`
}

// socialRedirectError maps sentinel resolution errors onto portal error codes.
func socialRedirectError(err error) (string, bool) {
	switch {
	case errors.Is(err, errSocialAccountDisabled):
		return socialErrAccountDisabled, true
	case errors.Is(err, errSocialNotRegistered):
		return socialErrNotRegistered, true
	}
	return "", false
}
