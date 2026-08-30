package kv

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	// Miss -> ErrNotFound.
	if _, err := store.Get(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("get missing: err = %v, want ErrNotFound", err)
	}

	// Set/Get round trip without TTL.
	if err := store.Set(ctx, "k1", "v1", 0); err != nil {
		t.Fatalf("set: %v", err)
	}
	if v, err := store.Get(ctx, "k1"); err != nil || v != "v1" {
		t.Fatalf("get k1: v=%q err=%v", v, err)
	}
	ttl, err := store.TTL(ctx, "k1")
	if err != nil {
		t.Fatalf("ttl: %v", err)
	}
	if ttl >= 0 {
		t.Fatalf("ttl of persistent key = %v, want negative", ttl)
	}

	// TTL expiry.
	if err := store.Set(ctx, "k2", "v2", 30*time.Millisecond); err != nil {
		t.Fatalf("set: %v", err)
	}
	if ttl, err := store.TTL(ctx, "k2"); err != nil || ttl <= 0 {
		t.Fatalf("ttl k2: ttl=%v err=%v", ttl, err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := store.Get(ctx, "k2"); err != ErrNotFound {
		t.Fatalf("get expired k2: err = %v, want ErrNotFound", err)
	}

	// Del.
	_ = store.Set(ctx, "k3", "v3", 0)
	if err := store.Del(ctx, "k3"); err != nil {
		t.Fatalf("del: %v", err)
	}
	if _, err := store.Get(ctx, "k3"); err != ErrNotFound {
		t.Fatalf("get deleted: err = %v, want ErrNotFound", err)
	}
}

func TestMemoryStoreIncr(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	// First incr creates at 1 and applies the TTL.
	n, err := store.Incr(ctx, "counter", time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("first incr: n=%d err=%v", n, err)
	}
	if ttl, err := store.TTL(ctx, "counter"); err != nil || ttl <= 0 || ttl > time.Minute {
		t.Fatalf("ttl after create: ttl=%v err=%v", ttl, err)
	}

	// Subsequent incrs keep the original expiry.
	time.Sleep(5 * time.Millisecond)
	first, _ := store.TTL(ctx, "counter")
	for i := 0; i < 4; i++ {
		n, err = store.Incr(ctx, "counter", 5*time.Minute)
		if err != nil {
			t.Fatalf("incr: %v", err)
		}
	}
	if n != 5 {
		t.Fatalf("counter = %d, want 5", n)
	}
	second, _ := store.TTL(ctx, "counter")
	if second > first {
		t.Fatalf("ttl must not be extended by incr: %v > %v", second, first)
	}

	// Incr with ttl<=0 creates a persistent counter.
	if _, err := store.Incr(ctx, "ver", 0); err != nil {
		t.Fatalf("incr: %v", err)
	}
	if ttl, err := store.TTL(ctx, "ver"); err != nil || ttl >= 0 {
		t.Fatalf("persistent counter ttl = %v err = %v", ttl, err)
	}
}
