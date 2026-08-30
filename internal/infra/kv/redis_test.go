package kv

import (
	"context"
	"testing"
	"time"

	"github.com/flametest/vita/vredis"
)

// Compile-time assertions: both stores must satisfy Store.
var _ Store = (*RedisStore)(nil)

// TestRedisStoreSmoke exercises the RedisStore against a live Redis when one
// is running locally. It is skipped with -short (CI needs no Redis) and when
// no Redis answers on 127.0.0.1:6379, so the suite stays green everywhere.
func TestRedisStoreSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping redis smoke test in short mode")
	}
	ctx := context.Background()
	client := vredis.NewClient(vredis.Config{Addr: "127.0.0.1:6379", DialTimeout: 1})
	defer func() { _ = client.Close() }()

	if _, err := client.Get(ctx, "__access_hub_smoke__"); err != nil {
		t.Skipf("no live redis available: %v", err)
	}

	store := NewRedisStore(client)
	key := "access-hub:kv:smoke"

	if err := store.Set(ctx, key, "42", time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	if v, err := store.Get(ctx, key); err != nil || v != "42" {
		t.Fatalf("get: v=%q err=%v", v, err)
	}
	if ttl, err := store.TTL(ctx, key); err != nil || ttl <= 0 {
		t.Fatalf("ttl: ttl=%v err=%v", ttl, err)
	}
	if n, err := store.Incr(ctx, key+":ctr", time.Minute); err != nil || n != 1 {
		t.Fatalf("incr: n=%d err=%v", n, err)
	}
	if err := store.Del(ctx, key); err != nil {
		t.Fatalf("del: %v", err)
	}
	if err := store.Del(ctx, key+":ctr"); err != nil {
		t.Fatalf("del ctr: %v", err)
	}
	if _, err := store.Get(ctx, key); err != ErrNotFound {
		t.Fatalf("get after del: err = %v, want ErrNotFound", err)
	}
}
