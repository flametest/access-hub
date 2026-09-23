package oauth2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/flametest/access-hub/internal/infra/kv"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
)

// TestGetByCodeConsumesAtomically pins the single-use enforcement: the first
// presentation of an authorization code wins, every later one — concurrent
// or not — sees an invalid code (pre-fix the load and the remove were two
// steps, so two racing exchanges of the same code could both proceed).
func TestGetByCodeConsumesAtomically(t *testing.T) {
	store := NewTokenStore(kv.NewMemoryStore(), nil)
	ctx := context.Background()
	err := store.Create(ctx, &model2Token{
		Code:          "code-1",
		CodeCreateAt:  time.Now(),
		CodeExpiresIn: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create code: %v", err)
	}
	if _, err := store.GetByCode(ctx, "code-1"); err != nil {
		t.Fatalf("first presentation must win: %v", err)
	}
	if _, err := store.GetByCode(ctx, "code-1"); !errors.Is(err, oauth2errors.ErrInvalidAuthorizeCode) {
		t.Fatalf("second presentation must be invalid, got %v", err)
	}
}
