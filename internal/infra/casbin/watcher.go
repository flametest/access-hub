package casbinx

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/flametest/vita/vlog"
	"github.com/flametest/vita/vredis"
	"github.com/redis/go-redis/v9"
)

// ReloadChannel is the Redis pub/sub channel used to broadcast policy reloads
// to all access-hub instances.
const ReloadChannel = "casbin:reload"

// RedisWatcher is a minimal hand-rolled casbin watcher: on reload messages
// published to ReloadChannel it invokes the update callback (typically
// Enforcer.Reload). Auto-reconnecting subscription via go-redis Channel().
type RedisWatcher struct {
	client    *redis.Client
	pubsub    *redis.PubSub
	closed    chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	callback func(string)
}

// NewRedisWatcher creates the watcher and starts the subscription goroutine.
// onReload is invoked (with panic recovery) for every reload message; pass
// enforcer.Reload here. The watcher is only useful when Redis is reachable;
// subscription failures are logged and retried by the go-redis Channel
// machinery, so a temporarily missing Redis does not crash the process.
func NewRedisWatcher(cfg vredis.Config, onReload func()) *RedisWatcher {
	opts := &redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	}
	if cfg.DialTimeout > 0 {
		opts.DialTimeout = time.Duration(cfg.DialTimeout) * time.Second
	}
	client := redis.NewClient(opts)

	// Wrap the zero-arg onReload into the casbin callback shape (payload is
	// informational; every message means "reload").
	var cb func(string)
	if onReload != nil {
		cb = func(string) { onReload() }
	}
	w := &RedisWatcher{
		client:   client,
		pubsub:   client.Subscribe(context.Background(), ReloadChannel),
		closed:   make(chan struct{}),
		callback: cb,
	}
	go w.loop()
	return w
}

// loop consumes pub/sub messages until Close. go-redis Channel() handles
// reconnects internally and closes the channel when the PubSub is closed.
func (w *RedisWatcher) loop() {
	msgs := w.pubsub.Channel(redis.WithChannelSize(16))
	for {
		select {
		case <-w.closed:
			return
		case msg, ok := <-msgs:
			if !ok {
				return
			}
			w.dispatch(msg.Payload)
		}
	}
}

func (w *RedisWatcher) dispatch(payload string) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Any("panic", r).Msg("casbin watcher reload callback panicked")
		}
	}()
	w.mu.Lock()
	cb := w.callback
	w.mu.Unlock()
	if cb != nil {
		cb(payload)
	}
}

// SetUpdateCallback replaces the reload callback (part of the casbin
// persist.Watcher interface).
func (w *RedisWatcher) SetUpdateCallback(cb func(string)) error {
	w.mu.Lock()
	w.callback = cb
	w.mu.Unlock()
	return nil
}

// UpdateCallback returns the current reload callback.
func (w *RedisWatcher) UpdateCallback() func(string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.callback
}

// Update implements persist.Watcher: publish the reload broadcast.
func (w *RedisWatcher) Update() error { return w.Notify() }

// Notify publishes a reload message to all instances. Errors are returned so
// callers can log them; they do not block the write path.
func (w *RedisWatcher) Notify() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.client.Publish(ctx, ReloadChannel, "reload").Err(); err != nil {
		return fmt.Errorf("publish casbin reload: %w", err)
	}
	return nil
}

// Close stops the subscription and releases the Redis connection. Safe on a
// partially-initialized watcher.
func (w *RedisWatcher) Close() {
	w.closeOnce.Do(func() {
		close(w.closed)
		if w.pubsub != nil {
			_ = w.pubsub.Close()
		}
		if w.client != nil {
			_ = w.client.Close()
		}
	})
}

// Compile-time check that the watcher satisfies the casbin interface.
var _ interface {
	SetUpdateCallback(func(string)) error
	Update() error
	Close()
} = (*RedisWatcher)(nil)
