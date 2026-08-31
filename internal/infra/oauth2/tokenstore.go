package oauth2

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/vita/vgorm"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/google/uuid"
)

// kv key namespaces for the go-oauth2 stores.
const (
	// kvCodePrefix holds serialized authorization-code TokenInfo records
	// (code storage/expiry stays inside the library's manager; the records
	// carry the PKCE challenge and the authorize-time extension).
	kvCodePrefix = "oauth:code:"
	// kvRetiredPrefix maps a rotated refresh-token hash to its row id so
	// reuse of a rotated token is detected and revokes the family.
	kvRetiredPrefix = "oauth:rt:retired:"
)

// RetiredHashPrefix is exported for the service layer's refresh-rotation
// reuse detection (same key space as this store).
const RetiredHashPrefix = kvRetiredPrefix

// TokenStore adapts the KV store (authorization codes) and the
// oauth_refresh_tokens table (refresh tokens) to the go-oauth2 TokenStore.
// Access tokens are self-contained RS256 JWTs and are intentionally NOT
// persisted (GetByAccess is always a miss).
type TokenStore struct {
	kv          kv.Store
	refreshRepo repository.OAuthRefreshTokenRepo
}

var _ oauth2.TokenStore = (*TokenStore)(nil)

// NewTokenStore builds the adapter.
func NewTokenStore(store kv.Store, refreshRepo repository.OAuthRefreshTokenRepo) *TokenStore {
	return &TokenStore{kv: store, refreshRepo: refreshRepo}
}

// Create persists the TokenInfo: codes go to the KV store with their expiry;
// refresh tokens become oauth_refresh_tokens rows (user/account subjects
// carried from the code's UserID and the authorize-time extension).
func (s *TokenStore) Create(ctx context.Context, ti oauth2.TokenInfo) error {
	if code := ti.GetCode(); code != "" {
		raw, err := json.Marshal(toStorageToken(ti))
		if err != nil {
			return err
		}
		ttl := ti.GetCodeExpiresIn()
		if ttl <= 0 {
			ttl = 10 * time.Minute
		}
		return s.kv.Set(ctx, kvCodePrefix+code, string(raw), ttl)
	}
	if refresh := ti.GetRefresh(); refresh != "" {
		row := &model.OAuthRefreshToken{
			BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
			ClientID:     ti.GetClientID(),
			TokenHash:    sha256Hex(refresh),
			Scope:        ti.GetScope(),
			ExpiresAt:    ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()),
		}
		if row.ExpiresAt.IsZero() {
			row.ExpiresAt = time.Now().Add(ti.GetRefreshExpiresIn())
		}
		// Subjects come from the authorize-time extension: account_id is the
		// resolved workspace account (the access-token subject), user_id the
		// owning identity.
		if ext, ok := ti.(oauth2.ExtendableTokenInfo); ok {
			if aid := ext.GetExtension().Get("account_id"); aid != "" {
				a := aid
				row.AccountID = &a
			}
			if iid := ext.GetExtension().Get("iid"); iid != "" {
				u := iid
				row.UserID = &u
			}
		}
		return s.refreshRepo.Create(ctx, row)
	}
	return nil
}

// RemoveByCode deletes the code record (single-use enforcement).
func (s *TokenStore) RemoveByCode(ctx context.Context, code string) error {
	return s.kv.Del(ctx, kvCodePrefix+code)
}

// GetByCode loads the code record.
func (s *TokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	raw, err := s.kv.Get(ctx, kvCodePrefix+code)
	if err != nil {
		if err == kv.ErrNotFound {
			return nil, errors.ErrInvalidAuthorizeCode
		}
		return nil, err
	}
	var ti model2Token
	if err := json.Unmarshal([]byte(raw), &ti); err != nil {
		return nil, err
	}
	return &ti, nil
}

// GetByAccess is always a miss: access tokens are self-contained JWTs.
func (s *TokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return nil, errors.ErrInvalidAccessToken
}

// RemoveByAccess is a no-op for the same reason.
func (s *TokenStore) RemoveByAccess(ctx context.Context, access string) error { return nil }

// GetByRefresh resolves a refresh token row (used by the library's refresh
// path; the service layer implements the rotation semantics itself).
func (s *TokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	row, err := s.refreshRepo.FindByTokenHash(ctx, sha256Hex(refresh))
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, errors.ErrInvalidRefreshToken
		}
		return nil, err
	}
	if row.RevokedAt != nil {
		return nil, errors.ErrInvalidRefreshToken
	}
	ti := &model2Token{
		ClientID:         row.ClientID,
		Scope:            row.Scope,
		Refresh:          refresh,
		RefreshCreateAt:  row.CreatedAt,
		RefreshExpiresIn: time.Until(row.ExpiresAt),
	}
	if row.AccountID != nil {
		ti.UserID = "account:" + *row.AccountID
	}
	return ti, nil
}

// RemoveByRefresh revokes the matching row outright.
func (s *TokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	row, err := s.refreshRepo.FindByTokenHash(ctx, sha256Hex(refresh))
	if err != nil {
		if repository.IsNotFound(err) {
			return nil
		}
		return err
	}
	return s.refreshRepo.Revoke(ctx, row.Id, time.Now())
}

// toStorageToken copies any TokenInfo into the JSON-tagged storage shape.
func toStorageToken(ti oauth2.TokenInfo) *model2Token {
	st := &model2Token{
		ClientID:            ti.GetClientID(),
		UserID:              ti.GetUserID(),
		RedirectURI:         ti.GetRedirectURI(),
		Scope:               ti.GetScope(),
		Code:                ti.GetCode(),
		CodeChallenge:       ti.GetCodeChallenge(),
		CodeChallengeMethod: string(ti.GetCodeChallengeMethod()),
		CodeCreateAt:        ti.GetCodeCreateAt(),
		CodeExpiresIn:       ti.GetCodeExpiresIn(),
		Access:              ti.GetAccess(),
		AccessCreateAt:      ti.GetAccessCreateAt(),
		AccessExpiresIn:     ti.GetAccessExpiresIn(),
		Refresh:             ti.GetRefresh(),
		RefreshCreateAt:     ti.GetRefreshCreateAt(),
		RefreshExpiresIn:    ti.GetRefreshExpiresIn(),
		Extension:           urlValues{},
	}
	if ext, ok := ti.(oauth2.ExtendableTokenInfo); ok {
		for k, vs := range ext.GetExtension() {
			st.Extension[k] = vs
		}
	}
	return st
}

// model2Token is the storage shape of serialized TokenInfo records (the
// library's models.Token uses bson tags, so an equivalent local struct with
// json tags keeps the KV records compact and portable).
type model2Token struct {
	ClientID            string        `json:"client_id"`
	UserID              string        `json:"user_id"`
	RedirectURI         string        `json:"redirect_uri"`
	Scope               string        `json:"scope"`
	Code                string        `json:"code"`
	CodeChallenge       string        `json:"code_challenge"`
	CodeChallengeMethod string        `json:"code_challenge_method"`
	CodeCreateAt        time.Time     `json:"code_create_at"`
	CodeExpiresIn       time.Duration `json:"code_expires_in"`
	Access              string        `json:"access"`
	AccessCreateAt      time.Time     `json:"access_create_at"`
	AccessExpiresIn     time.Duration `json:"access_expires_in"`
	Refresh             string        `json:"refresh"`
	RefreshCreateAt     time.Time     `json:"refresh_create_at"`
	RefreshExpiresIn    time.Duration `json:"refresh_expires_in"`
	Extension           urlValues     `json:"extension"`
}

// urlValues is a JSON-friendly stand-in for url.Values (map[string][]string).
type urlValues map[string][]string

var (
	_ oauth2.TokenInfo           = (*model2Token)(nil)
	_ oauth2.ExtendableTokenInfo = (*model2Token)(nil)
)

func (t *model2Token) New() oauth2.TokenInfo            { return &model2Token{} }
func (t *model2Token) GetClientID() string              { return t.ClientID }
func (t *model2Token) SetClientID(v string)             { t.ClientID = v }
func (t *model2Token) GetUserID() string                { return t.UserID }
func (t *model2Token) SetUserID(v string)               { t.UserID = v }
func (t *model2Token) GetRedirectURI() string           { return t.RedirectURI }
func (t *model2Token) SetRedirectURI(v string)          { t.RedirectURI = v }
func (t *model2Token) GetScope() string                 { return t.Scope }
func (t *model2Token) SetScope(v string)                { t.Scope = v }
func (t *model2Token) GetCode() string                  { return t.Code }
func (t *model2Token) SetCode(v string)                 { t.Code = v }
func (t *model2Token) GetCodeCreateAt() time.Time       { return t.CodeCreateAt }
func (t *model2Token) SetCodeCreateAt(v time.Time)      { t.CodeCreateAt = v }
func (t *model2Token) GetCodeExpiresIn() time.Duration  { return t.CodeExpiresIn }
func (t *model2Token) SetCodeExpiresIn(v time.Duration) { t.CodeExpiresIn = v }
func (t *model2Token) GetCodeChallenge() string         { return t.CodeChallenge }
func (t *model2Token) SetCodeChallenge(v string)        { t.CodeChallenge = v }
func (t *model2Token) GetCodeChallengeMethod() oauth2.CodeChallengeMethod {
	return oauth2.CodeChallengeMethod(t.CodeChallengeMethod)
}
func (t *model2Token) SetCodeChallengeMethod(v oauth2.CodeChallengeMethod) {
	t.CodeChallengeMethod = string(v)
}
func (t *model2Token) GetAccess() string                   { return t.Access }
func (t *model2Token) SetAccess(v string)                  { t.Access = v }
func (t *model2Token) GetAccessCreateAt() time.Time        { return t.AccessCreateAt }
func (t *model2Token) SetAccessCreateAt(v time.Time)       { t.AccessCreateAt = v }
func (t *model2Token) GetAccessExpiresIn() time.Duration   { return t.AccessExpiresIn }
func (t *model2Token) SetAccessExpiresIn(v time.Duration)  { t.AccessExpiresIn = v }
func (t *model2Token) GetRefresh() string                  { return t.Refresh }
func (t *model2Token) SetRefresh(v string)                 { t.Refresh = v }
func (t *model2Token) GetRefreshCreateAt() time.Time       { return t.RefreshCreateAt }
func (t *model2Token) SetRefreshCreateAt(v time.Time)      { t.RefreshCreateAt = v }
func (t *model2Token) GetRefreshExpiresIn() time.Duration  { return t.RefreshExpiresIn }
func (t *model2Token) SetRefreshExpiresIn(v time.Duration) { t.RefreshExpiresIn = v }
func (t *model2Token) GetExtension() url.Values            { return url.Values(t.Extension) }
func (t *model2Token) SetExtension(v url.Values)           { t.Extension = urlValues(v) }
