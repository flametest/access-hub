// Admin management of OAuth2/OIDC clients (design.md §12 M4). Secrets are
// generated once (sec_<32hex>), returned in plaintext only in the create
// response and stored as sha256 hashes. The Casbin loader translates active
// client_credentials clients into wildcard rules for their own app; status
// changes therefore trigger a policy reload.
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
)

// AdminOAuthClientService manages OIDC client registrations per app.
type AdminOAuthClientService interface {
	List(ctx context.Context, actor *AdminActor, appKey string) ([]dto.OAuthClientItem, error)
	Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateOAuthClientReq) (*dto.CreateOAuthClientResp, error)
	Update(ctx context.Context, actor *AdminActor, appKey, clientID string, req *dto.UpdateOAuthClientReq) (*dto.OAuthClientItem, error)
	Delete(ctx context.Context, actor *AdminActor, appKey, clientID string) error
}

type adminOAuthClientServiceImpl struct {
	c container.Container
}

// NewAdminOAuthClientService builds the admin oauth-client service.
func NewAdminOAuthClientService(c container.Container) AdminOAuthClientService {
	return &adminOAuthClientServiceImpl{c: c}
}

func (s *adminOAuthClientServiceImpl) toItem(row *model.OAuthClient, appKey string) dto.OAuthClientItem {
	return dto.OAuthClientItem{
		ClientID:     row.Id,
		AppKey:       appKey,
		Name:         row.Name,
		ClientType:   row.ClientType,
		GrantTypes:   jsonStringsOf(row.GrantTypes),
		RedirectURIs: jsonStringsOf(row.RedirectURIs),
		Scopes:       jsonStringsOf(row.Scopes),
		Status:       row.Status,
		CreatedAt:    row.CreatedAt,
	}
}

// appByKey loads the app and enforces the caller's org scope.
func (s *adminOAuthClientServiceImpl) appByKey(ctx context.Context, actor *AdminActor, appKey string) (*model.App, error) {
	return actor.accessibleApp(ctx, s.c, appKey)
}

// validateClientInput checks client_type / grant_types / redirect_uris /
// scopes invariants shared by create and update.
func validateClientInput(clientType string, grants, redirectURIs, scopes []string) error {
	if clientType != "" && clientType != model.OAuthClientTypeConfidential && clientType != model.OAuthClientTypePublic {
		return verrors.BadRequestError("client_type must be confidential or public")
	}
	for _, g := range grants {
		switch g {
		case model.OAuthGrantAuthorizationCode, model.OAuthGrantRefreshToken, model.OAuthGrantClientCredentials:
		default:
			return verrors.BadRequestError("grant_types entries must be authorization_code, refresh_token or client_credentials")
		}
	}
	if hasGrant(grants, model.OAuthGrantClientCredentials) && clientType == model.OAuthClientTypePublic {
		return verrors.BadRequestError("public clients cannot use the client_credentials grant")
	}
	if hasGrant(grants, model.OAuthGrantAuthorizationCode) && len(redirectURIs) == 0 {
		return verrors.BadRequestError("authorization_code clients require at least one redirect_uri")
	}
	for _, raw := range redirectURIs {
		uri, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || uri.Scheme == "" || uri.Host == "" || uri.Fragment != "" {
			return verrors.BadRequestError("redirect_uris entries must be absolute https(s) URLs without fragments")
		}
	}
	for _, sc := range scopes {
		if strings.TrimSpace(sc) == "" || strings.ContainsAny(sc, " ") {
			return verrors.BadRequestError("scopes entries must be non-empty and contain no spaces")
		}
	}
	return nil
}

func hasGrant(grants []string, want string) bool {
	for _, g := range grants {
		if g == want {
			return true
		}
	}
	return false
}

func (s *adminOAuthClientServiceImpl) List(ctx context.Context, actor *AdminActor, appKey string) ([]dto.OAuthClientItem, error) {
	app, err := s.appByKey(ctx, actor, appKey)
	if err != nil {
		return nil, err
	}
	rows, err := s.c.OAuthClientRepo().FindByApp(ctx, app.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "list oauth clients")
	}
	out := make([]dto.OAuthClientItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.toItem(row, app.Key))
	}
	return out, nil
}

// newClientID generates the cli_<16hex> identifier.
func newClientID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", verrors.InternalServerError("generate client_id")
	}
	return "cli_" + hex.EncodeToString(buf), nil
}

// newClientSecret generates the sec_<32hex> plaintext secret (shown once).
func newClientSecret() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", verrors.InternalServerError("generate client_secret")
	}
	return "sec_" + hex.EncodeToString(buf), nil
}

func (s *adminOAuthClientServiceImpl) Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateOAuthClientReq) (*dto.CreateOAuthClientResp, error) {
	app, err := s.appByKey(ctx, actor, appKey)
	if err != nil {
		return nil, err
	}
	if err := validateClientInput(req.ClientType, req.GrantTypes, req.RedirectURIs, req.Scopes); err != nil {
		return nil, err
	}
	clientID, err := newClientID()
	if err != nil {
		return nil, err
	}
	row := &model.OAuthClient{
		BasePostgres: vgorm.BasePostgres{Id: clientID},
		AppID:        app.Id,
		Name:         req.Name,
		ClientType:   req.ClientType,
		GrantTypes:   encodeJSONStrings(dedupe(req.GrantTypes)),
		RedirectURIs: encodeJSONStrings(dedupe(req.RedirectURIs)),
		Scopes:       encodeJSONStrings(dedupe(req.Scopes)),
		Status:       model.OAuthClientStatusActive,
	}
	resp := &dto.CreateOAuthClientResp{OAuthClientItem: s.toItem(row, app.Key)}
	if req.ClientType == model.OAuthClientTypeConfidential {
		secret, err := newClientSecret()
		if err != nil {
			return nil, err
		}
		hash := sha256Hex(secret)
		row.SecretHash = &hash
		resp.ClientSecret = secret
	}
	if err := s.c.OAuthClientRepo().Create(ctx, row); err != nil {
		return nil, verrors.Wrap(err, "create oauth client")
	}
	resp.OAuthClientItem = s.toItem(row, app.Key)
	writeAudit(ctx, s.c, ActorIdentity, actor.IdentityID, app.OrgID, AuditOAuthClientCreated, "oauth_client", row.Id,
		map[string]any{"app_key": app.Key, "client_type": row.ClientType, "grant_types": req.GrantTypes}, "", "")
	return resp, nil
}

func (s *adminOAuthClientServiceImpl) Update(ctx context.Context, actor *AdminActor, appKey, clientID string, req *dto.UpdateOAuthClientReq) (*dto.OAuthClientItem, error) {
	app, err := s.appByKey(ctx, actor, appKey)
	if err != nil {
		return nil, err
	}
	row, err := s.c.OAuthClientRepo().FindByID(ctx, clientID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("oauth client not found")
		}
		return nil, verrors.Wrap(err, "find oauth client")
	}
	if row.AppID != app.Id {
		return nil, verrors.NotFoundError("oauth client not found")
	}
	fields := map[string]any{}
	if req.Name != nil {
		fields["name"] = *req.Name
	}
	if req.Status != nil {
		if *req.Status != model.OAuthClientStatusActive && *req.Status != model.OAuthClientStatusDisabled {
			return nil, verrors.BadRequestError("status must be active or disabled")
		}
		fields["status"] = *req.Status
	}
	if req.GrantTypes != nil {
		if err := validateClientInput(row.ClientType, req.GrantTypes, jsonStringsOf(row.RedirectURIs), jsonStringsOf(row.Scopes)); err != nil {
			return nil, err
		}
		fields["grant_types"] = encodeJSONStrings(dedupe(req.GrantTypes))
	}
	if req.RedirectURIs != nil {
		if err := validateClientInput(row.ClientType, jsonStringsOf(row.GrantTypes), req.RedirectURIs, jsonStringsOf(row.Scopes)); err != nil {
			return nil, err
		}
		fields["redirect_uris"] = encodeJSONStrings(dedupe(req.RedirectURIs))
	}
	if req.Scopes != nil {
		if err := validateClientInput(row.ClientType, jsonStringsOf(row.GrantTypes), jsonStringsOf(row.RedirectURIs), req.Scopes); err != nil {
			return nil, err
		}
		fields["scopes"] = encodeJSONStrings(dedupe(req.Scopes))
	}
	if len(fields) > 0 {
		if err := s.c.OAuthClientRepo().UpdateFields(ctx, row.Id, fields); err != nil {
			return nil, verrors.Wrap(err, "update oauth client")
		}
	}
	// Status changes affect the loader's service-client rules: broadcast a
	// reload so every instance drops/picks up the wildcard rule.
	if status, ok := fields["status"]; ok {
		_ = casbinNotify(ctx, s.c, []string{app.Key})
		writeAudit(ctx, s.c, ActorIdentity, actor.IdentityID, app.OrgID, AuditOAuthClientUpdated, "oauth_client", row.Id,
			map[string]any{"status": status, "app_key": app.Key}, "", "")
	} else {
		writeAudit(ctx, s.c, ActorIdentity, actor.IdentityID, app.OrgID, AuditOAuthClientUpdated, "oauth_client", row.Id,
			map[string]any{"fields": len(fields), "app_key": app.Key}, "", "")
	}
	updated, err := s.c.OAuthClientRepo().FindByID(ctx, row.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "reload oauth client")
	}
	item := s.toItem(updated, app.Key)
	return &item, nil
}

func (s *adminOAuthClientServiceImpl) Delete(ctx context.Context, actor *AdminActor, appKey, clientID string) error {
	app, err := s.appByKey(ctx, actor, appKey)
	if err != nil {
		return err
	}
	row, err := s.c.OAuthClientRepo().FindByID(ctx, clientID)
	if err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("oauth client not found")
		}
		return verrors.Wrap(err, "find oauth client")
	}
	if row.AppID != app.Id {
		return verrors.NotFoundError("oauth client not found")
	}
	if err := s.c.OAuthClientRepo().Delete(ctx, row.Id); err != nil {
		return verrors.Wrap(err, "delete oauth client")
	}
	// Soft-deleted clients also drop out of the loader on the next reload.
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	writeAudit(ctx, s.c, ActorIdentity, actor.IdentityID, app.OrgID, AuditOAuthClientDeleted, "oauth_client", row.Id,
		map[string]any{"app_key": app.Key}, "", "")
	return nil
}

// dedupe removes empty strings and duplicates, keeping order.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
