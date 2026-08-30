package kv

import (
	"context"
	"errors"
	"time"

	"github.com/flametest/vita/vredis"
	"github.com/redis/go-redis/v9"
)

// RedisStore implements Store on top of the vita vredis client.
type RedisStore struct {
	client vredis.Client
}

var _ Store = (*RedisStore)(nil)

// NewRedisStore wraps a vredis client (shared with the rest of the app).
func NewRedisStore(client vredis.Client) *RedisStore {
	return &RedisStore{client: client}
}

func (s *RedisStore) Get(ctx context.Context, key string) (string, error) {
	val, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrNotFound
		}
		return "", err
	}
	return val, nil
}

func (s *RedisStore) Set(ctx context.Context, key, val string, ttl time.Duration) error {
	if ttl < 0 {
		ttl = 0
	}
	return s.client.Set(ctx, key, val, ttl)
}

func (s *RedisStore) Del(ctx context.Context, key string) error {
	return s.client.Del(ctx, key)
}

// Incr increments the counter; the TTL is applied only when the increment
// created the key (value becomes 1), matching the Store contract.
func (s *RedisStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := s.client.Incr(ctx, key)
	if err != nil {
		return 0, err
	}
	if n == 1 && ttl > 0 {
		if err := s.client.Expire(ctx, key, ttl); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (s *RedisStore) TTL(ctx context.Context, key string) (time.Duration, error) {
	d, err := s.client.TTL(ctx, key)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if d == -2*time.Second {
		return 0, ErrNotFound
	}
	return d, nil
}
