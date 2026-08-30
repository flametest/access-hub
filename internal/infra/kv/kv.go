// Package kv provides a small key/value abstraction over Redis (production)
// or an in-memory map (tests). Used for email codes, rate limiting, session
// denylist and the Casbin policy version counters.
package kv

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Get/TTL when the key does not exist (or expired).
var ErrNotFound = errors.New("kv: key not found")

// Store is the key/value contract used across access-hub.
type Store interface {
	// Get returns the value; ErrNotFound on a miss.
	Get(ctx context.Context, key string) (string, error)
	// Set writes the value with a TTL. ttl <= 0 means no expiry.
	Set(ctx context.Context, key, val string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
	// Incr atomically increments the counter, creating it at 1 when missing.
	// TTL is applied only on creation (so retries don't extend the window).
	// ttl <= 0 creates a key without expiry.
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	// TTL returns the remaining time-to-live. ErrNotFound when the key is
	// missing; -1 signals a key without expiry (Redis semantics).
	TTL(ctx context.Context, key string) (time.Duration, error)
}
