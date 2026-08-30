package casbinx

import (
	"context"
	"errors"
	"strconv"

	"github.com/flametest/access-hub/internal/infra/kv"
)

// policyVersionKeyPrefix is the Redis key namespace for per-app policy
// versions (`policy:ver:{appKey}`) used for downstream cache invalidation and
// periodic reconciliation (design.md §2.4).
const policyVersionKeyPrefix = "policy:ver:"

// PolicyVersionKey builds the Redis key for an app's policy version.
func PolicyVersionKey(appKey string) string {
	return policyVersionKeyPrefix + appKey
}

// GetPolicyVersion returns the app's current policy version; a missing key
// reads as 0 (nothing published yet).
func GetPolicyVersion(ctx context.Context, store kv.Store, appKey string) (int64, error) {
	raw, err := store.Get(ctx, PolicyVersionKey(appKey))
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return 0, nil
		}
		return 0, err
	}
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, errors.New("casbin: corrupted policy version value " + raw)
	}
	return version, nil
}

// IncrPolicyVersion atomically bumps the app's policy version, creating it at
// 1 when missing. The key is permanent (no TTL).
func IncrPolicyVersion(ctx context.Context, store kv.Store, appKey string) (int64, error) {
	return store.Incr(ctx, PolicyVersionKey(appKey), 0)
}
