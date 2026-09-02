package casbinx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/flametest/access-hub/internal/infra/kv"
)

func TestReconcilerReloadsOnEpochDivergence(t *testing.T) {
	store := kv.NewMemoryStore()
	reloads := 0
	failing := false
	rec := NewReconciler(store, func() error {
		reloads++
		if failing {
			return errors.New("loader unavailable")
		}
		return nil
	}, time.Hour)

	ctx := context.Background()
	loaded := int64(0)

	// No epoch published yet: nothing to do.
	if err := rec.checkOnce(ctx, &loaded); err != nil {
		t.Fatalf("checkOnce: %v", err)
	}
	if reloads != 0 {
		t.Fatalf("baseline check must not reload, got %d", reloads)
	}

	// A mutation bumps the epoch: the next check reloads and adopts the
	// post-reload epoch.
	if _, err := BumpGlobalEpoch(ctx, store); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if err := rec.checkOnce(ctx, &loaded); err != nil {
		t.Fatalf("checkOnce: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("divergent epoch must trigger exactly one reload, got %d", reloads)
	}

	// No further mutation: idempotent no-op.
	if err := rec.checkOnce(ctx, &loaded); err != nil {
		t.Fatalf("checkOnce: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("converged state must not reload, got %d", reloads)
	}

	// A failed reload keeps the stale epoch so the next tick retries.
	failing = true
	if _, err := BumpGlobalEpoch(ctx, store); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if err := rec.checkOnce(ctx, &loaded); err == nil {
		t.Fatal("failing reload must surface an error")
	}
	failing = false
	if err := rec.checkOnce(ctx, &loaded); err != nil {
		t.Fatalf("retry checkOnce: %v", err)
	}
	if reloads != 3 {
		t.Fatalf("expected failed attempt + successful retry = 3 reloads, got %d", reloads)
	}
}

func TestReconcilerStopTerminates(t *testing.T) {
	store := kv.NewMemoryStore()
	rec := NewReconciler(store, func() error { return nil }, time.Millisecond)
	if err := rec.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	rec.Stop()
	// Stop must be prompt and idempotent-safe (a second Stop would panic on
	// double close — documented single-use lifecycle).
	select {
	case <-rec.doneCh:
	case <-time.After(time.Second):
		t.Fatal("Stop did not terminate the goroutine")
	}
}
