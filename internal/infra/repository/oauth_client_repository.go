package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// OAuthClientRepo persists OIDC relying-party registrations (oauth_clients).
type OAuthClientRepo interface {
	Create(ctx context.Context, client *model.OAuthClient) error
	// FindByID resolves a client by its client_id (the primary key).
	FindByID(ctx context.Context, clientID string) (*model.OAuthClient, error)
	FindByApp(ctx context.Context, appID string) ([]*model.OAuthClient, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	// Delete soft-deletes the client; zero rows yields NotFoundError.
	Delete(ctx context.Context, id string) error
	CountByApp(ctx context.Context, appID string) (int64, error)
	// ListActiveClientCredential returns every ACTIVE client allowed to use
	// the client_credentials grant (Casbin loader data source: each becomes
	// "p, client:{id}, app:{appKey}, *, *").
	ListActiveClientCredential(ctx context.Context) ([]*model.OAuthClient, error)
}

type oauthClientRepoImpl struct {
	db *gorm.DB
}

func NewOAuthClientRepo(db *gorm.DB) OAuthClientRepo {
	return &oauthClientRepoImpl{db: db}
}

func (r *oauthClientRepoImpl) Create(ctx context.Context, client *model.OAuthClient) error {
	return r.db.WithContext(ctx).Create(client).Error
}

func (r *oauthClientRepoImpl) FindByID(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	var client model.OAuthClient
	if err := r.db.WithContext(ctx).Where("id = ?", clientID).First(&client).Error; err != nil {
		return nil, translateFirst(err, "oauth client %s not found", clientID)
	}
	return &client, nil
}

func (r *oauthClientRepoImpl) FindByApp(ctx context.Context, appID string) ([]*model.OAuthClient, error) {
	var out []*model.OAuthClient
	err := r.db.WithContext(ctx).
		Where("app_id = ?", appID).
		Order("created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *oauthClientRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.OAuthClient{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("oauth client %s not found", id))
}

func (r *oauthClientRepoImpl) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.OAuthClient{})
	return updateRowsAffected(res, fmt.Sprintf("oauth client %s not found", id))
}

func (r *oauthClientRepoImpl) CountByApp(ctx context.Context, appID string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.OAuthClient{}).Where("app_id = ?", appID).Count(&count).Error
	return count, err
}

// ListActiveClientCredential filters active clients in memory (the grant
// types live in a jsonb column whose SQL predicates differ per dialect).
func (r *oauthClientRepoImpl) ListActiveClientCredential(ctx context.Context) ([]*model.OAuthClient, error) {
	var out []*model.OAuthClient
	err := r.db.WithContext(ctx).
		Where("status = ?", model.OAuthClientStatusActive).
		Find(&out).Error
	if err != nil {
		return nil, err
	}
	filtered := make([]*model.OAuthClient, 0, len(out))
	for _, row := range out {
		for _, g := range decodeJSONStrings(row.GrantTypes) {
			if g == model.OAuthGrantClientCredentials {
				filtered = append(filtered, row)
				break
			}
		}
	}
	return filtered, nil
}

// decodeJSONStrings decodes a jsonb string-array column, tolerating nil input.
func decodeJSONStrings(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}
