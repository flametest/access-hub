package service

import (
	"context"
	"strings"
	"testing"

	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/password"
	"github.com/flametest/access-hub/internal/testutil"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
)

func newAuthEnv(t *testing.T) (*testutil.TestContainer, AuthService, TokenService) {
	t.Helper()
	tc := testutil.New(t)
	return tc, NewAuthService(tc), NewTokenService(tc)
}

func seedIdentity(t *testing.T, tc *testutil.TestContainer, username, email, pw string) *model.User {
	t.Helper()
	hash, err := password.Hash(pw, tc.Cfg().Auth.BcryptCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user := &model.User{
		BasePostgres:  vgorm.BasePostgres{Id: uuid.NewString()},
		Username:      username,
		Email:         email,
		EmailVerified: true,
		PasswordHash:  &hash,
		Status:        domain.UserStatusActive,
	}
	if err := tc.UserRepo().Create(context.Background(), user); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return user
}

// TestRefreshRotationAndReuse covers the in-place rotation contract: a
// refresh rotates the same session row (rotation_count++), the previous
// token becomes unusable and its replay revokes the whole session.
func TestRefreshRotationAndReuse(t *testing.T) {
	tc, authSvc, tokenSvc := newAuthEnv(t)
	ctx := context.Background()
	user := seedIdentity(t, tc, "alice", "alice@test.dev", "AlicePassw0rd")

	pair1, err := tokenSvc.IdentityPair(ctx, user, "agent-1", "10.0.0.1")
	if err != nil {
		t.Fatalf("identity pair: %v", err)
	}
	sessionID := pair1.SessionID

	// First refresh: same session row, rotation_count bumped, new token.
	session, newRefresh, err := tokenSvc.Rotate(ctx, pair1.RefreshToken)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if session.Id != sessionID {
		t.Fatalf("rotation changed session id: %s != %s", session.Id, sessionID)
	}
	if session.RotationCount != 1 {
		t.Fatalf("rotation_count = %d, want 1", session.RotationCount)
	}
	if newRefresh == pair1.RefreshToken {
		t.Fatal("rotation must issue a new opaque token")
	}
	if _, err := tokenSvc.PairFromSession(ctx, session, newRefresh); err != nil {
		t.Fatalf("pair from session: %v", err)
	}

	// Reuse of the rotated-away token: detected and revokes the session.
	_, _, err = tokenSvc.Rotate(ctx, pair1.RefreshToken)
	if err == nil {
		t.Fatal("reused refresh token must be rejected")
	}
	var vErr *verrors.Error
	if !verrors.As(err, &vErr) || vErr.ErrCode() != verrors.UnauthorizedCode {
		t.Fatalf("reuse error = %v, want 1401", err)
	}
	row, err := tc.SessionRepo().FindByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("find session: %v", err)
	}
	if row.RevokedAt == nil {
		t.Fatal("reuse must revoke the whole session")
	}

	// The successor token is dead too (session revoked) and unknown tokens 401.
	if _, _, err := tokenSvc.Rotate(ctx, newRefresh); err == nil {
		t.Fatal("successor token must be rejected after session revocation")
	}
	if _, _, err := tokenSvc.Rotate(ctx, "not-a-real-token"); err == nil {
		t.Fatal("unknown refresh token must be rejected")
	}

	// The auth service refresh endpoint surfaces the same semantics.
	if _, err := authSvc.Refresh(ctx, &dto.RefreshReq{RefreshToken: pair1.RefreshToken}); err == nil {
		t.Fatal("auth refresh of a reused token must fail")
	}
}

// TestBruteforceLockout covers the login guard: failures increment the
// counters, reaching the limit locks the key (even for correct passwords)
// and a successful login clears the counters.
func TestBruteforceLockout(t *testing.T) {
	tc, authSvc, _ := newAuthEnv(t)
	ctx := context.Background()
	max := 3
	tc.Cfg().Auth.LoginMaxAttempts = max
	user := seedIdentity(t, tc, "brutus", "brutus@test.dev", "BrutusPassw0rd")

	// max failures reach the lock.
	for i := 0; i < max; i++ {
		_, err := authSvc.Login(ctx, &dto.LoginReq{Identifier: user.Email, Password: "WrongPassw0rd"}, "agent", "9.9.9.9")
		if err == nil {
			t.Fatalf("attempt %d must fail", i+1)
		}
		var vErr *verrors.Error
		if verrors.As(err, &vErr) && vErr.ErrCode() == verrors.ForbiddenCode {
			t.Fatalf("attempt %d locked too early: %v", i+1, err)
		}
	}
	// Lock keys: the (ip, identifier) pair tripped at the configured
	// threshold; the per-ip key only trips at 10x (spraying backstop).
	if _, err := tc.KV().Get(ctx, "login:lock:pair:9.9.9.9:"+user.Email); err != nil {
		t.Fatalf("pair lock key missing: %v", err)
	}
	if _, err := tc.KV().Get(ctx, "login:lock:ip:9.9.9.9"); err == nil {
		t.Fatal("per-ip lock must not trip at the pair threshold")
	}

	// Anti-lockout-DoS: the same failures must NOT lock the victim logging
	// in from another IP (there is no per-identifier key anymore).
	_, err := authSvc.Login(ctx, &dto.LoginReq{Identifier: user.Email, Password: "BrutusPassw0rd"}, "agent", "8.8.8.8")
	if err != nil {
		t.Fatalf("victim login from another IP must succeed, got %v", err)
	}

	// Even the correct password is rejected while locked (1403).
	_, err = authSvc.Login(ctx, &dto.LoginReq{Identifier: user.Email, Password: "BrutusPassw0rd"}, "agent", "9.9.9.9")
	var vErr *verrors.Error
	if !verrors.As(err, &vErr) || vErr.ErrCode() != verrors.ForbiddenCode {
		t.Fatalf("locked login error = %v, want 1403", err)
	}

	// Successful login clears the counters.
	_ = tc.KV().Del(ctx, "login:lock:pair:9.9.9.9:"+user.Email)
	_ = tc.KV().Del(ctx, "login:lock:ip:9.9.9.9")
	resp, err := authSvc.Login(ctx, &dto.LoginReq{Identifier: user.Email, Password: "BrutusPassw0rd"}, "agent", "9.9.9.9")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" || resp.TokenType != "Bearer" {
		t.Fatal("login must return a Bearer token pair")
	}
	if _, err := tc.KV().Get(ctx, "login:fail:pair:9.9.9.9:"+user.Email); err != kv.ErrNotFound {
		t.Fatal("success must clear the failure counter")
	}

	// account-login uses the app-scoped key too.
	app := &model.App{Key: "crm", Name: "CRM", Status: domain.AppStatusActive}
	if err := tc.AppRepo().Create(ctx, app); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	hash, _ := password.Hash("BobPassw0rd", tc.Cfg().Auth.BcryptCost)
	account := &model.Account{
		IdentityID:   user.Id,
		AppID:        app.Id,
		Email:        "bob@test.dev",
		PasswordHash: &hash,
		Status:       domain.AccountStatusActive,
		Source:       domain.AccountSourceProvisioned,
	}
	if err := tc.AccountRepo().Create(ctx, account); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	for i := 0; i < max; i++ {
		_, _ = authSvc.AccountLogin(ctx, &dto.AccountLoginReq{App: "crm", Identifier: "bob@test.dev", Password: "NopePassw0rd"}, "agent", "9.9.9.8")
	}
	_, err = authSvc.AccountLogin(ctx, &dto.AccountLoginReq{App: "crm", Identifier: "bob@test.dev", Password: "BobPassw0rd"}, "agent", "9.9.9.8")
	if !verrors.As(err, &vErr) || vErr.ErrCode() != verrors.ForbiddenCode {
		t.Fatalf("account lock error = %v, want 1403", err)
	}
	if _, err := tc.KV().Get(ctx, "login:lock:app:crm:bob@test.dev"); err != nil {
		t.Fatalf("app-scoped lock key missing: %v", err)
	}
}

// TestEmailCodeAttemptLimits covers the verification-code attempt counter:
// after EmailCodeMaxAttempts failed attempts the code is invalidated, and a
// fresh correct code is consumed exactly once.
func TestEmailCodeAttemptLimits(t *testing.T) {
	tc, authSvc, _ := newAuthEnv(t)
	ctx := context.Background()
	email := "codee@test.dev"
	seedIdentity(t, tc, "codee", email, "CodeePassw0rd")

	// Send: 202-equivalent (no error), code recorded hashed with TTL.
	if err := authSvc.SendEmailCode(ctx, &dto.SendEmailCodeReq{Email: email, Purpose: "login"}, "7.7.7.7"); err != nil {
		t.Fatalf("send code: %v", err)
	}
	body := tc.Mail.Last().Body
	code := ""
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "verification code is:") {
			code = strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}
	if len(code) != 6 {
		t.Fatalf("could not extract code from mailer body %q", body)
	}
	key := "email:code:login:" + email
	if _, err := tc.KV().Get(ctx, key); err != nil {
		t.Fatalf("code not stored: %v", err)
	}

	// Wrong attempts burn the code after the configured limit.
	max := tc.Cfg().Auth.EmailCodeMaxAttempts
	for i := 0; i < max; i++ {
		if _, err := authSvc.EmailLogin(ctx, &dto.EmailLoginReq{Email: email, Code: "000000"}, "agent", "7.7.7.7"); err == nil {
			t.Fatalf("wrong code attempt %d must fail", i+1)
		}
	}
	// The counter reached the limit and deleted the stored code: even the
	// correct code is now rejected.
	if _, err := authSvc.EmailLogin(ctx, &dto.EmailLoginReq{Email: email, Code: code}, "agent", "7.7.7.7"); err == nil {
		t.Fatal("code must be invalidated after max failed attempts")
	}
	if _, err := tc.KV().Get(ctx, key); err != kv.ErrNotFound {
		t.Fatal("code must be deleted after max failed attempts")
	}

	// A fresh code verifies once and is consumed (clear the 60s send-rate key
	// the first send left behind, and the login-guard keys the wrong guesses
	// tripped — this test targets the per-code counter, not the lock).
	_ = tc.KV().Del(ctx, "rl:sendcode:"+email)
	_ = tc.KV().Del(ctx, "login:lock:eml:"+email)
	_ = tc.KV().Del(ctx, "login:lock:ip:7.7.7.7")
	if err := authSvc.SendEmailCode(ctx, &dto.SendEmailCodeReq{Email: email, Purpose: "login"}, "7.7.7.7"); err != nil {
		t.Fatalf("send code: %v", err)
	}
	code = ""
	for _, line := range strings.Split(tc.Mail.Last().Body, "\n") {
		if strings.Contains(line, "verification code is:") {
			code = strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}
	resp, err := authSvc.EmailLogin(ctx, &dto.EmailLoginReq{Email: email, Code: code}, "agent", "7.7.7.7")
	if err != nil {
		t.Fatalf("email login: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("email login must return tokens")
	}
	if _, err := tc.KV().Get(ctx, key); err != kv.ErrNotFound {
		t.Fatal("verified code must be consumed")
	}
}

// TestEmailLoginAutoRegister covers the AllowAutoRegister path for unknown
// emails: a passwordless identity is created with a derived username.
func TestEmailLoginAutoRegister(t *testing.T) {
	tc, authSvc, _ := newAuthEnv(t)
	ctx := context.Background()
	email := "newbie@test.dev"
	if err := authSvc.SendEmailCode(ctx, &dto.SendEmailCodeReq{Email: email, Purpose: "login"}, "7.7.7.8"); err != nil {
		t.Fatalf("send code: %v", err)
	}
	code := ""
	for _, line := range strings.Split(tc.Mail.Last().Body, "\n") {
		if strings.Contains(line, "verification code is:") {
			code = strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}
	resp, err := authSvc.EmailLogin(ctx, &dto.EmailLoginReq{Email: email, Code: code}, "agent", "7.7.7.8")
	if err != nil {
		t.Fatalf("email login: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("auto register must still return tokens")
	}
	user, err := tc.UserRepo().FindByEmail(ctx, email)
	if err != nil {
		t.Fatalf("auto-registered user missing: %v", err)
	}
	if !strings.HasPrefix(user.Username, "user_") || len(user.Username) != len("user_")+6 {
		t.Fatalf("derived username = %q, want user_{rand6}", user.Username)
	}
	if !user.EmailVerified || user.PasswordHash != nil {
		t.Fatal("auto-registered identity must be verified and passwordless")
	}
}

// TestEmailLoginGuessLockoutSurvivesResend pins the brute-force fix: wrong
// code attempts accumulate into the per-email login lock, and resending a
// fresh code does NOT reset it — the correct code stays unusable while the
// lock is held (pre-fix: every 60s resend granted a fresh attempt budget).
func TestEmailLoginGuessLockoutSurvivesResend(t *testing.T) {
	tc, authSvc, _ := newAuthEnv(t)
	ctx := context.Background()
	email := "brutef@test.dev"
	seedIdentity(t, tc, "brutef", email, "BrutePassw0rd")

	sendCode := func() string {
		t.Helper()
		_ = tc.KV().Del(ctx, "rl:sendcode:"+email)
		if err := authSvc.SendEmailCode(ctx, &dto.SendEmailCodeReq{Email: email, Purpose: "login"}, "9.9.9.9"); err != nil {
			t.Fatalf("send code: %v", err)
		}
		code := ""
		for _, line := range strings.Split(tc.Mail.Last().Body, "\n") {
			if strings.Contains(line, "verification code is:") {
				code = strings.TrimSpace(strings.Split(line, ":")[1])
			}
		}
		if len(code) != 6 {
			t.Fatalf("could not extract code from mailer body %q", tc.Mail.Last().Body)
		}
		return code
	}

	sendCode()
	// EmailCodeMaxAttempts wrong guesses burn the code; the next wrong guess
	// counts against the login guard and reaches the lock threshold.
	max := tc.Cfg().Auth.LoginMaxAttempts
	for i := 0; i < max; i++ {
		if _, err := authSvc.EmailLogin(ctx, &dto.EmailLoginReq{Email: email, Code: "000000"}, "agent", "9.9.9.9"); err == nil {
			t.Fatalf("wrong code attempt %d must fail", i+1)
		}
	}

	// A resent (correct!) code must NOT bypass the lock.
	code2 := sendCode()
	if _, err := authSvc.EmailLogin(ctx, &dto.EmailLoginReq{Email: email, Code: code2}, "agent", "9.9.9.9"); err == nil {
		t.Fatal("login must stay locked despite a fresh correct code")
	}
	if _, err := tc.KV().Get(ctx, "login:lock:eml:"+email); err != nil {
		t.Fatalf("email lock key must be set: %v", err)
	}

	// A different IP is not locked by this email's guard on its own — but its
	// wrong guesses still count toward the email key, so a successful login
	// from another IP needs a fresh code and works once the email lock
	// expires. Cover the success path after manually expiring the lock (both
	// the email and the ip guard keys tripped).
	_ = tc.KV().Del(ctx, "login:lock:eml:"+email)
	_ = tc.KV().Del(ctx, "login:lock:ip:9.9.9.9")
	code3 := sendCode()
	resp, err := authSvc.EmailLogin(ctx, &dto.EmailLoginReq{Email: email, Code: code3}, "agent", "9.9.9.9")
	if err != nil {
		t.Fatalf("login after lock expiry must succeed: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("login must return tokens")
	}
}

// TestLoginEnumerationIsUniform pins the anti-enumeration contract: an
// unknown identifier, a disabled identity and a passwordless identity all
// answer with the SAME 401 "invalid credentials" a wrong password gets.
func TestLoginEnumerationIsUniform(t *testing.T) {
	tc, authSvc, _ := newAuthEnv(t)
	ctx := context.Background()
	user := seedIdentity(t, tc, "enumy", "enumy@test.dev", "EnumyPassw0rd")

	assertInvalidCredentials := func(name string, err error) {
		t.Helper()
		var vErr *verrors.Error
		if !verrors.As(err, &vErr) || vErr.ErrCode() != verrors.UnauthorizedCode ||
			!strings.Contains(err.Error(), "invalid credentials") {
			t.Fatalf("%s must be 401 invalid credentials, got %v", name, err)
		}
	}

	// Unknown identifier (time-equalized with a dummy bcrypt comparison).
	_, err := authSvc.Login(ctx, &dto.LoginReq{Identifier: "ghost@test.dev", Password: "WhateverPass1"}, "agent", "6.6.6.1")
	assertInvalidCredentials("unknown identifier", err)

	// Disabled identity.
	if err := tc.UserRepo().UpdateFields(ctx, user.Id, map[string]any{"status": domain.UserStatusDisabled}); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	_, err = authSvc.Login(ctx, &dto.LoginReq{Identifier: user.Email, Password: "EnumyPassw0rd"}, "agent", "6.6.6.2")
	assertInvalidCredentials("disabled identity", err)

	// Passwordless identity (email-code-only account).
	if err := tc.UserRepo().UpdateFields(ctx, user.Id, map[string]any{
		"status": domain.UserStatusActive, "password_hash": nil,
	}); err != nil {
		t.Fatalf("clear password: %v", err)
	}
	_, err = authSvc.Login(ctx, &dto.LoginReq{Identifier: user.Email, Password: "EnumyPassw0rd"}, "agent", "6.6.6.3")
	assertInvalidCredentials("passwordless identity", err)
}
