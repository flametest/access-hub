package service

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/password"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
)

// kv key namespaces for the login guards and email codes.
const (
	kvLoginLockPrefix  = "login:lock:"
	kvLoginFailPrefix  = "login:fail:"
	kvSendCodePrefix   = "rl:sendcode:"
	kvSendCodeIPPrefix = "rl:sendcode:ip:"
	kvEmailCodePrefix  = "email:code:"
	kvEmailAttPrefix   = "email:code:att:"

	// EmailCodePurposeSetPassword is the purpose for first-time identity
	// password codes (auto-provisioned identities).
	EmailCodePurposeSetPassword = "set_password"
)

// AuthService implements the public authentication endpoints.
type AuthService interface {
	Register(ctx context.Context, req *dto.RegisterReq, device, ip string) (*dto.RegisterResp, error)
	Login(ctx context.Context, req *dto.LoginReq, device, ip string) (*dto.LoginResp, error)
	// Login2FA completes the 2FA login challenge (TOTP or backup code).
	Login2FA(ctx context.Context, req *dto.Login2FAReq, device, ip string) (*dto.LoginResp, error)
	AccountLogin(ctx context.Context, req *dto.AccountLoginReq, device, ip string) (*dto.AccountTokenResp, error)
	SendEmailCode(ctx context.Context, req *dto.SendEmailCodeReq, ip string) error
	EmailLogin(ctx context.Context, req *dto.EmailLoginReq, device, ip string) (*dto.LoginResp, error)
	PasswordSet(ctx context.Context, req *dto.PasswordSetReq) error
	PasswordReset(ctx context.Context, req *dto.PasswordResetReq) error
	AccountActivate(ctx context.Context, req *dto.AccountActivateReq) (*dto.AccountActivateResp, error)
	Refresh(ctx context.Context, req *dto.RefreshReq) (*dto.TokenPair, error)
	Logout(ctx context.Context, refreshToken string, claims *ClaimsLike) error
}

// ClaimsLike is the minimal claim view Logout needs (keeps the service free
// of the JWT package types).
type ClaimsLike struct {
	Subject   string
	Audience  string
	ID        string // jti
	SessionID string
	ExpiresAt time.Time
	IsAccount bool
}

type authServiceImpl struct {
	c     container.Container
	token TokenService
}

// NewAuthService builds the auth service.
func NewAuthService(c container.Container) AuthService {
	return &authServiceImpl{c: c, token: NewTokenService(c)}
}

// ---------- registration & logins ----------

func (s *authServiceImpl) Register(ctx context.Context, req *dto.RegisterReq, device, ip string) (*dto.RegisterResp, error) {
	username := strings.ToLower(strings.TrimSpace(req.Username))
	email := normalizeEmail(req.Email)
	if err := password.ValidatePolicy(req.Password); err != nil {
		return nil, err
	}
	if _, err := s.c.UserRepo().FindByUsername(ctx, username); err == nil {
		return nil, verrors.ConflictError("username already taken")
	} else if !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find user by username")
	}
	if _, err := s.c.UserRepo().FindByEmail(ctx, email); err == nil {
		return nil, verrors.ConflictError("email already registered")
	} else if !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find user by email")
	}
	hash, err := password.Hash(req.Password, s.c.Cfg().Auth.BcryptCost)
	if err != nil {
		return nil, err
	}
	user := &model.User{
		BasePostgres:  vgorm.BasePostgres{Id: uuid.NewString()},
		Username:      username,
		Email:         email,
		EmailVerified: false,
		PasswordHash:  &hash,
		Status:        domain.UserStatusActive,
	}
	if req.Nickname != "" {
		n := req.Nickname
		user.Nickname = &n
	}
	if err := s.c.UserRepo().Create(ctx, user); err != nil {
		return nil, verrors.Wrap(err, "create user")
	}
	// Register is exempt from the 2FA challenge: the identity is brand new
	// and cannot have a confirmed TOTP enrollment yet.
	pair, err := s.token.IdentityPair(ctx, user, device, ip)
	if err != nil {
		return nil, err
	}
	writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditLoginSuccess, "user", user.Id,
		map[string]any{"via": "register"}, ip, device)
	return &dto.RegisterResp{
		TokenPair: *toTokenPair(pair, device, ip),
		Me:        toMe(user, false),
	}, nil
}

func (s *authServiceImpl) Login(ctx context.Context, req *dto.LoginReq, device, ip string) (*dto.LoginResp, error) {
	identifier := strings.ToLower(strings.TrimSpace(req.Identifier))
	keys := []string{"idt:" + identifier, "ip:" + ip}
	if err := s.checkLoginLock(ctx, keys); err != nil {
		return nil, err
	}
	user, err := s.c.UserRepo().FindByUsernameOrEmail(ctx, identifier)
	if err != nil {
		if !repository.IsNotFound(err) {
			return nil, verrors.Wrap(err, "find user by identifier")
		}
		s.recordLoginFailure(ctx, keys)
		writeAudit(ctx, s.c, ActorSystem, "", nil, AuditLoginFailed, "identifier", identifier,
			map[string]any{"reason": "unknown identifier"}, ip, device)
		return nil, verrors.UnauthorizedError("invalid credentials")
	}
	if user.Status != domain.UserStatusActive {
		s.recordLoginFailure(ctx, keys)
		writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditLoginFailed, "user", user.Id,
			map[string]any{"reason": "disabled"}, ip, device)
		return nil, verrors.ForbiddenError("account disabled")
	}
	if user.PasswordHash == nil || *user.PasswordHash == "" {
		s.recordLoginFailure(ctx, keys)
		writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditLoginFailed, "user", user.Id,
			map[string]any{"reason": "no password set"}, ip, device)
		return nil, verrors.ForbiddenError("password not set, sign in with an email code first")
	}
	if err := password.Verify(*user.PasswordHash, req.Password); err != nil {
		s.recordLoginFailure(ctx, keys)
		writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditLoginFailed, "user", user.Id,
			map[string]any{"reason": "bad password"}, ip, device)
		return nil, err
	}
	s.clearLoginFailures(ctx, keys)
	_ = s.c.UserRepo().TouchLastLogin(ctx, user.Id, time.Now())
	// 2FA optional enhancement: a confirmed TOTP enrollment turns the login
	// into a two-step challenge — no tokens until /auth/login/2fa succeeds.
	if twoFAConfirmed(ctx, s.c, user.Id) {
		mfaToken, err := s.c.JWT().Issue(jwt.NewMFAClaims(user.Id, s.c.Cfg().Auth.MFATokenTTL))
		if err != nil {
			return nil, err
		}
		return &dto.LoginResp{MfaRequired: true, MfaToken: mfaToken}, nil
	}
	pair, err := s.token.IdentityPair(ctx, user, device, ip)
	if err != nil {
		return nil, err
	}
	writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditLoginSuccess, "user", user.Id,
		map[string]any{"via": "password"}, ip, device)
	return toLoginResp(pair, device, ip), nil
}

func (s *authServiceImpl) AccountLogin(ctx context.Context, req *dto.AccountLoginReq, device, ip string) (*dto.AccountTokenResp, error) {
	appKey := strings.ToLower(strings.TrimSpace(req.App))
	app, err := s.c.AppRepo().FindByKey(ctx, appKey)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("app not found")
		}
		return nil, verrors.Wrap(err, "find app")
	}
	if app.Status != domain.AppStatusActive {
		return nil, verrors.ForbiddenError("app is disabled")
	}
	identifier := strings.ToLower(strings.TrimSpace(req.Identifier))
	keys := []string{"app:" + appKey + ":" + identifier, "idt:" + identifier, "ip:" + ip}
	if err := s.checkLoginLock(ctx, keys); err != nil {
		return nil, err
	}
	fail := func(reason string) error {
		s.recordLoginFailure(ctx, keys)
		writeAudit(ctx, s.c, ActorSystem, "", nil, AuditLoginFailed, "app", appKey,
			map[string]any{"reason": reason, "identifier": identifier}, ip, device)
		return verrors.UnauthorizedError("invalid credentials")
	}
	account, err := s.c.AccountRepo().FindByAppAndEmail(ctx, app.Id, identifier)
	if err != nil && repository.IsNotFound(err) {
		account, err = s.c.AccountRepo().FindByAppAndUsername(ctx, app.Id, identifier)
	}
	if err != nil {
		if !repository.IsNotFound(err) {
			return nil, verrors.Wrap(err, "find account")
		}
		return nil, fail("unknown account")
	}
	if account.Status != domain.AccountStatusActive {
		s.recordLoginFailure(ctx, keys)
		writeAudit(ctx, s.c, ActorAccount, account.Id, app.OrgID, AuditLoginFailed, "account", account.Id,
			map[string]any{"reason": "status " + account.Status}, ip, device)
		if account.Status == domain.AccountStatusPendingActivation {
			return nil, verrors.ForbiddenError("account pending activation, check your activation email")
		}
		return nil, verrors.ForbiddenError("account disabled")
	}
	if account.PasswordHash == nil || *account.PasswordHash == "" {
		// Auto-provisioned (SSO) accounts have no password until activated.
		s.recordLoginFailure(ctx, keys)
		writeAudit(ctx, s.c, ActorAccount, account.Id, app.OrgID, AuditLoginFailed, "account", account.Id,
			map[string]any{"reason": "no password set"}, ip, device)
		return nil, verrors.ForbiddenError("password not set, use the activation email to set one")
	}
	identity, err := s.c.UserRepo().FindByID(ctx, account.IdentityID)
	if err != nil {
		return nil, verrors.Wrap(err, "find account identity")
	}
	if identity.Status != domain.UserStatusActive {
		s.recordLoginFailure(ctx, keys)
		return nil, verrors.ForbiddenError("account disabled")
	}
	if err := password.Verify(*account.PasswordHash, req.Password); err != nil {
		s.recordLoginFailure(ctx, keys)
		writeAudit(ctx, s.c, ActorAccount, account.Id, app.OrgID, AuditLoginFailed, "account", account.Id,
			map[string]any{"reason": "bad password"}, ip, device)
		return nil, err
	}
	s.clearLoginFailures(ctx, keys)
	_ = s.c.AccountRepo().TouchLastLogin(ctx, account.Id, time.Now())
	pair, err := s.token.AccountPair(ctx, account, app, identity, device, ip)
	if err != nil {
		return nil, err
	}
	writeAudit(ctx, s.c, ActorAccount, account.Id, app.OrgID, AuditLoginSuccess, "account", account.Id,
		map[string]any{"via": "password", "app_key": appKey}, ip, device)
	return &dto.AccountTokenResp{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
		AccountID:    account.Id,
		AppKey:       appKey,
	}, nil
}

// ---------- email codes ----------

func (s *authServiceImpl) SendEmailCode(ctx context.Context, req *dto.SendEmailCodeReq, ip string) error {
	email := normalizeEmail(req.Email)
	cfg := s.c.Cfg().Auth
	// Anti-enumeration: always answer 202 regardless of account existence.
	if n, err := s.c.KV().Incr(ctx, kvSendCodePrefix+email, 60*time.Second); err == nil && n > 1 {
		return verrors.ConflictError("verification code already sent, please try again later")
	}
	if n, err := s.c.KV().Incr(ctx, kvSendCodeIPPrefix+ip, time.Hour); err == nil && n > int64(cfg.SendCodeIPLimit) {
		return verrors.ConflictError("too many codes requested, please try again later")
	}
	code, err := randomDigits(6)
	if err != nil {
		return verrors.InternalServerError(fmt.Sprintf("generate code: %v", err))
	}
	if err := s.c.KV().Set(ctx, kvEmailCodePrefix+req.Purpose+":"+email, sha256Hex(code), cfg.EmailCodeTTL); err != nil {
		return verrors.Wrap(err, "store email code")
	}
	_ = s.c.KV().Del(ctx, kvEmailAttPrefix+req.Purpose+":"+email)
	subject := "Access-Hub verification code"
	body := fmt.Sprintf("Your Access-Hub verification code is: %s\n\nIt expires in %s.", code, cfg.EmailCodeTTL)
	if err := s.c.Mailer().Send(ctx, email, subject, body); err != nil {
		return verrors.Wrap(err, "send email code")
	}
	return nil
}

// checkEmailCode verifies (and consumes) a hashed email code. Failed attempts
// are counted; once the limit is reached the code is invalidated.
func (s *authServiceImpl) checkEmailCode(ctx context.Context, purpose, email, code string) error {
	key := kvEmailCodePrefix + purpose + ":" + email
	stored, err := s.c.KV().Get(ctx, key)
	if err != nil {
		if err == kv.ErrNotFound {
			return verrors.UnauthorizedError("invalid or expired verification code")
		}
		return verrors.Wrap(err, "load email code")
	}
	cfg := s.c.Cfg().Auth
	attKey := kvEmailAttPrefix + purpose + ":" + email
	attempts, _ := s.c.KV().Incr(ctx, attKey, cfg.EmailCodeTTL)
	if attempts >= int64(cfg.EmailCodeMaxAttempts) {
		_ = s.c.KV().Del(ctx, key)
		_ = s.c.KV().Del(ctx, attKey)
		return verrors.UnauthorizedError("invalid or expired verification code")
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(sha256Hex(code))) != 1 {
		return verrors.UnauthorizedError("invalid or expired verification code")
	}
	_ = s.c.KV().Del(ctx, key)
	_ = s.c.KV().Del(ctx, attKey)
	return nil
}

func (s *authServiceImpl) EmailLogin(ctx context.Context, req *dto.EmailLoginReq, device, ip string) (*dto.LoginResp, error) {
	email := normalizeEmail(req.Email)
	if err := s.checkEmailCode(ctx, "login", email, req.Code); err != nil {
		return nil, err
	}
	user, err := s.c.UserRepo().FindByEmail(ctx, email)
	if err != nil {
		if !repository.IsNotFound(err) {
			return nil, verrors.Wrap(err, "find user by email")
		}
		if !s.c.Cfg().Auth.AllowAutoRegister {
			return nil, verrors.NotFoundError("no account for this email")
		}
		username, err := deriveUniqueUsername(ctx, s.c.UserRepo())
		if err != nil {
			return nil, err
		}
		user = &model.User{
			BasePostgres:  vgorm.BasePostgres{Id: uuid.NewString()},
			Username:      username,
			Email:         email,
			EmailVerified: true,
			Status:        domain.UserStatusActive,
		}
		if err := s.c.UserRepo().Create(ctx, user); err != nil {
			return nil, verrors.Wrap(err, "auto register user")
		}
	}
	if user.Status != domain.UserStatusActive {
		return nil, verrors.ForbiddenError("account disabled")
	}
	_ = s.c.UserRepo().TouchLastLogin(ctx, user.Id, time.Now())
	// Same 2FA challenge as the password login (existing identities only;
	// freshly auto-registered identities have no enrollment).
	if twoFAConfirmed(ctx, s.c, user.Id) {
		mfaToken, err := s.c.JWT().Issue(jwt.NewMFAClaims(user.Id, s.c.Cfg().Auth.MFATokenTTL))
		if err != nil {
			return nil, err
		}
		return &dto.LoginResp{MfaRequired: true, MfaToken: mfaToken}, nil
	}
	pair, err := s.token.IdentityPair(ctx, user, device, ip)
	if err != nil {
		return nil, err
	}
	writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditLoginSuccess, "user", user.Id,
		map[string]any{"via": "email_code"}, ip, device)
	return toLoginResp(pair, device, ip), nil
}

// Login2FA completes the 2FA login challenge: the short-lived mfa_token from
// /auth/login (typ=mfa) plus a TOTP or backup code. Success issues the same
// identity token pair as a first-factor login.
func (s *authServiceImpl) Login2FA(ctx context.Context, req *dto.Login2FAReq, device, ip string) (*dto.LoginResp, error) {
	claims, err := s.c.JWT().Parse(strings.TrimSpace(req.MfaToken))
	if err != nil || !claims.IsMFAToken() {
		return nil, verrors.UnauthorizedError("invalid or expired mfa token")
	}
	userID := strings.TrimPrefix(claims.Subject, "user:")
	keys := []string{"mfa:" + userID, "ip:" + ip}
	if err := guardCheckLock(ctx, s.c, keys); err != nil {
		return nil, err
	}
	fail := func(reason string) error {
		guardRecordFailure(ctx, s.c, keys)
		writeAudit(ctx, s.c, ActorIdentity, userID, nil, AuditLoginFailed, "user", userID,
			map[string]any{"reason": reason, "step": "2fa"}, ip, device)
		return verrors.ForbiddenError("invalid verification code")
	}
	user, err := s.c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return nil, verrors.UnauthorizedError("invalid or expired mfa token")
	}
	if user.Status != domain.UserStatusActive {
		return nil, verrors.ForbiddenError("account disabled")
	}
	row, err := s.c.TOTPSecretRepo().FindByUserID(ctx, userID)
	if err != nil || !row.Confirmed {
		return nil, verrors.UnauthorizedError("invalid or expired mfa token")
	}
	if err := consumeTwoFACode(ctx, s.c, row, req.Code); err != nil {
		return nil, fail("bad_2fa_code")
	}
	guardClearFailures(ctx, s.c, keys)
	_ = s.c.UserRepo().TouchLastLogin(ctx, user.Id, time.Now())
	pair, err := s.token.IdentityPair(ctx, user, device, ip)
	if err != nil {
		return nil, err
	}
	writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditTwoFALogin, "user", user.Id,
		map[string]any{"via": "totp"}, ip, device)
	return toLoginResp(pair, device, ip), nil
}

// ---------- password flows ----------

func (s *authServiceImpl) PasswordSet(ctx context.Context, req *dto.PasswordSetReq) error {
	email := normalizeEmail(req.Email)
	if err := s.checkEmailCode(ctx, EmailCodePurposeSetPassword, email, req.Code); err != nil {
		return err
	}
	user, err := s.c.UserRepo().FindByEmail(ctx, email)
	if err != nil {
		return verrors.NotFoundError("no account for this email")
	}
	if user.PasswordHash != nil && *user.PasswordHash != "" {
		return verrors.ConflictError("password already set, use password reset instead")
	}
	if err := password.ValidatePolicy(req.NewPassword); err != nil {
		return err
	}
	hash, err := password.Hash(req.NewPassword, s.c.Cfg().Auth.BcryptCost)
	if err != nil {
		return err
	}
	if err := s.c.UserRepo().UpdateFields(ctx, user.Id, map[string]any{
		"password_hash":        hash,
		"email_verified":       true,
		"must_change_password": false,
	}); err != nil {
		return verrors.Wrap(err, "set password")
	}
	writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditPasswordChanged, "user", user.Id,
		map[string]any{"via": "email_code_set"}, "", "")
	return nil
}

func (s *authServiceImpl) PasswordReset(ctx context.Context, req *dto.PasswordResetReq) error {
	email := normalizeEmail(req.Email)
	if err := s.checkEmailCode(ctx, "reset", email, req.Code); err != nil {
		return err
	}
	user, err := s.c.UserRepo().FindByEmail(ctx, email)
	if err != nil {
		return verrors.NotFoundError("no account for this email")
	}
	if err := password.ValidatePolicy(req.NewPassword); err != nil {
		return err
	}
	hash, err := password.Hash(req.NewPassword, s.c.Cfg().Auth.BcryptCost)
	if err != nil {
		return err
	}
	if err := s.c.UserRepo().UpdateFields(ctx, user.Id, map[string]any{
		"password_hash":        hash,
		"must_change_password": false,
	}); err != nil {
		return verrors.Wrap(err, "reset password")
	}
	if err := s.c.SessionRepo().RevokeAllForUserByScope(ctx, user.Id, domain.SessionScopeIdentity, time.Now()); err != nil {
		return verrors.Wrap(err, "revoke identity sessions")
	}
	writeAudit(ctx, s.c, ActorIdentity, user.Id, nil, AuditPasswordReset, "user", user.Id,
		map[string]any{"via": "email_code_reset"}, "", "")
	return nil
}

func (s *authServiceImpl) AccountActivate(ctx context.Context, req *dto.AccountActivateReq) (*dto.AccountActivateResp, error) {
	appKey := strings.ToLower(strings.TrimSpace(req.App))
	app, err := s.c.AppRepo().FindByKey(ctx, appKey)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("app not found")
		}
		return nil, verrors.Wrap(err, "find app")
	}
	email := normalizeEmail(req.Email)
	account, err := s.c.AccountRepo().FindByAppAndEmail(ctx, app.Id, email)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("no account to activate for this email")
		}
		return nil, verrors.Wrap(err, "find account")
	}
	if err := s.checkEmailCode(ctx, "account_activate:"+appKey, email, req.Code); err != nil {
		return nil, err
	}
	if err := password.ValidatePolicy(req.NewPassword); err != nil {
		return nil, err
	}
	hash, err := password.Hash(req.NewPassword, s.c.Cfg().Auth.BcryptCost)
	if err != nil {
		return nil, err
	}
	if err := s.c.AccountRepo().UpdateFields(ctx, account.Id, map[string]any{
		"password_hash": hash,
		"status":        domain.AccountStatusActive,
	}); err != nil {
		return nil, verrors.Wrap(err, "activate account")
	}
	writeAudit(ctx, s.c, ActorIdentity, account.IdentityID, app.OrgID, AuditAccountActivated, "account", account.Id,
		map[string]any{"app_key": appKey}, "", "")
	return &dto.AccountActivateResp{
		AccountID: account.Id,
		AppKey:    appKey,
		Status:    domain.AccountStatusActive,
	}, nil
}

// ---------- refresh / logout ----------

func (s *authServiceImpl) Refresh(ctx context.Context, req *dto.RefreshReq) (*dto.TokenPair, error) {
	session, newRefresh, err := s.token.Rotate(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}
	pair, err := s.token.PairFromSession(ctx, session, newRefresh)
	if err != nil {
		return nil, err
	}
	return toTokenPair(pair, deref(session.Device), deref(session.IP)), nil
}

func (s *authServiceImpl) Logout(ctx context.Context, refreshToken string, claims *ClaimsLike) error {
	// Denylist the presented access token and revoke its session.
	if claims != nil && claims.ID != "" {
		remaining := time.Until(claims.ExpiresAt)
		if err := s.token.DenylistJTI(ctx, claims.ID, remaining); err != nil {
			return err
		}
		if claims.SessionID != "" {
			if err := s.token.RevokeSession(ctx, claims.SessionID); err != nil {
				return err
			}
		}
		actor := ActorIdentity
		actorID := strings.TrimPrefix(claims.Subject, "user:")
		if claims.IsAccount {
			actor = ActorAccount
			actorID = strings.TrimPrefix(claims.Subject, "account:")
		}
		writeAudit(ctx, s.c, actor, actorID, nil, AuditLogout, "session", claims.SessionID,
			map[string]any{"jti": claims.ID}, "", "")
	}
	// Also revoke a refresh token presented in the body (idempotent).
	if refreshToken != "" {
		session, err := s.c.SessionRepo().FindByTokenHash(ctx, sha256Hex(refreshToken))
		if err == nil {
			_ = s.token.RevokeSession(ctx, session.Id)
		}
	}
	return nil
}

// ---------- bruteforce guard ----------

// kv key prefixes for the 2FA challenge guard.
const (
	kvMFALockPrefix = "mfa:lock:"
	kvMFAFailPrefix = "mfa:fail:"
)

// checkLoginLock rejects the request when any applicable lock key is set.
func (s *authServiceImpl) checkLoginLock(ctx context.Context, keys []string) error {
	return guardCheckLock(ctx, s.c, keys)
}

// recordLoginFailure increments the failure counters and locks when the
// configured attempt limit is reached.
func (s *authServiceImpl) recordLoginFailure(ctx context.Context, keys []string) {
	guardRecordFailure(ctx, s.c, keys)
}

func (s *authServiceImpl) clearLoginFailures(ctx context.Context, keys []string) {
	guardClearFailures(ctx, s.c, keys)
}

// guardCheckLock is the shared lock check (login + 2FA challenge guards).
func guardCheckLock(ctx context.Context, c container.Container, keys []string) error {
	for _, key := range keys {
		if _, err := c.KV().Get(ctx, kvLoginLockPrefix+key); err == nil {
			writeAudit(ctx, c, ActorSystem, "", nil, AuditLoginLocked, "guard", key, nil, "", "")
			return verrors.ForbiddenError("account temporarily locked, try again later")
		}
	}
	return nil
}

// guardRecordFailure is the shared failure counter (login + 2FA guards).
func guardRecordFailure(ctx context.Context, c container.Container, keys []string) {
	cfg := c.Cfg().Auth
	for _, key := range keys {
		count, err := c.KV().Incr(ctx, kvLoginFailPrefix+key, cfg.LoginLockDuration)
		if err != nil {
			continue
		}
		if count >= int64(cfg.LoginMaxAttempts) {
			_ = c.KV().Set(ctx, kvLoginLockPrefix+key, "1", cfg.LoginLockDuration)
			_ = c.KV().Del(ctx, kvLoginFailPrefix+key)
			writeAudit(ctx, c, ActorSystem, "", nil, AuditLoginLocked, "guard", key, nil, "", "")
		}
	}
}

func guardClearFailures(ctx context.Context, c container.Container, keys []string) {
	for _, key := range keys {
		_ = c.KV().Del(ctx, kvLoginFailPrefix+key)
	}
}

// ---------- converters ----------

func toTokenPair(p *TokenPairResult, device, ip string) *dto.TokenPair {
	return &dto.TokenPair{
		AccessToken:  p.AccessToken,
		RefreshToken: p.RefreshToken,
		TokenType:    p.TokenType,
		ExpiresIn:    p.ExpiresIn,
		Session: &dto.SessionInfo{
			ID:     p.SessionID,
			Device: device,
			IP:     ip,
		},
	}
}

// toLoginResp maps a freshly issued token pair to the flat login response
// shape (LoginResp is no longer an embedded TokenPair: the 2FA challenge
// path returns mfa fields on the same object).
func toLoginResp(p *TokenPairResult, device, ip string) *dto.LoginResp {
	tp := toTokenPair(p, device, ip)
	return &dto.LoginResp{
		AccessToken:  tp.AccessToken,
		RefreshToken: tp.RefreshToken,
		TokenType:    tp.TokenType,
		ExpiresIn:    tp.ExpiresIn,
		Session:      tp.Session,
	}
}

// toMe maps a user row to the canonical /me payload. twoFAEnabled is the
// caller-resolved TOTP status (confirmed enrollment).
func toMe(u *model.User, twoFAEnabled bool) *dto.Me {
	return &dto.Me{
		ID:                 u.Id,
		Username:           u.Username,
		Email:              u.Email,
		EmailVerified:      u.EmailVerified,
		Nickname:           deref(u.Nickname),
		AvatarURL:          deref(u.AvatarURL),
		Status:             u.Status,
		MustChangePassword: u.MustChangePassword,
		TwoFAEnabled:       twoFAEnabled,
		CreatedAt:          u.CreatedAt,
		LastLoginAt:        u.LastLoginAt,
	}
}
