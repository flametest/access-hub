package casbinx

import (
	"context"
	"time"

	log "github.com/flametest/vita/vlog"

	"github.com/flametest/access-hub/internal/infra/kv"
)

// DefaultReconcileInterval is how often the reconciler compares the
// cluster-wide policy epoch with the epoch loaded into the local enforcer.
const DefaultReconcileInterval = 30 * time.Second

// Reconciler is the at-least-once convergence net for policy distribution:
// the Redis watcher is at-most-once (a dropped publish, a Redis restart or a
// subscriber gap would leave this instance stale forever), so every interval
// the global epoch in KV is compared with the epoch observed right after the
// local enforcer's last completed (re)load — divergence triggers a full
// reload. Reloads are idempotent, so a redundant reload after this
// instance's own mutation is harmless and additionally heals any drift the
// incremental sync missed.
type Reconciler struct {
	store    kv.Store
	reload   func() error
	interval time.Duration

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewReconciler builds a reconciler around a reload function (usually
// Enforcer.Reload). Call Start to run it.
func NewReconciler(store kv.Store, reload func() error, interval time.Duration) *Reconciler {
	if interval <= 0 {
		interval = DefaultReconcileInterval
	}
	return &Reconciler{
		store:    store,
		reload:   reload,
		interval: interval,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start captures the current epoch as the baseline (assuming the enforcer
// was fully loaded at construction) and spawns the ticker goroutine.
func (r *Reconciler) Start() error {
	baseline, err := GetGlobalEpoch(context.Background(), r.store)
	if err != nil {
		// The baseline only guards against a mutation raced between the
		// initial load and Start; a read failure is logged and retried on
		// the first tick rather than blocking startup.
		log.Warn().Any("error", err).Msg("policy reconciler: read baseline epoch failed, will retry on first tick")
	}
	loaded := baseline
	go func() {
		defer close(r.doneCh)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopCh:
				return
			case <-ticker.C:
				if err := r.checkOnce(context.Background(), &loaded); err != nil {
					log.Warn().Any("error", err).Msg("policy reconciler: check failed")
				}
			}
		}
	}()
	return nil
}

// checkOnce reloads when the cluster epoch moved past the locally loaded
// one. The epoch is re-read AFTER a successful reload so a mutation raced
// during the reload is picked up by the next tick instead of being skipped.
func (r *Reconciler) checkOnce(ctx context.Context, loaded *int64) error {
	epoch, err := GetGlobalEpoch(ctx, r.store)
	if err != nil {
		return err
	}
	if epoch == *loaded {
		return nil
	}
	if err := r.reload(); err != nil {
		// Keep the stale epoch so the next tick retries.
		return err
	}
	after, err := GetGlobalEpoch(ctx, r.store)
	if err != nil {
		// The reload itself succeeded; adopt the epoch we saw before it.
		*loaded = epoch
		return err
	}
	*loaded = after
	log.Info().Any("epoch", after).Msg("policy reconciler: reloaded stale policies")
	return nil
}

// Stop terminates the ticker goroutine and waits for it.
func (r *Reconciler) Stop() {
	close(r.stopCh)
	<-r.doneCh
}
