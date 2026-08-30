package kv

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// MemoryStore is a mutex-guarded in-memory Store for tests and local runs
// without Redis. Expired entries are dropped lazily on access.
type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]memoryEntry
}

var _ Store = (*MemoryStore)(nil)

type memoryEntry struct {
	value     string
	expiresAt time.Time // zero = no expiry
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]memoryEntry)}
}

func (s *MemoryStore) Get(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		return "", ErrNotFound
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		delete(s.entries, key)
		return "", ErrNotFound
	}
	return entry.value, nil
}

func (s *MemoryStore) Set(_ context.Context, key, val string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := memoryEntry{value: val}
	if ttl > 0 {
		entry.expiresAt = time.Now().Add(ttl)
	}
	s.entries[key] = entry
	return nil
}

func (s *MemoryStore) Del(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
	return nil
}

// Incr creates the key at 1 (with TTL) on first increment and preserves the
// original expiry on subsequent ones.
func (s *MemoryStore) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	entry, ok := s.entries[key]
	if !ok || (!entry.expiresAt.IsZero() && now.After(entry.expiresAt)) {
		newEntry := memoryEntry{value: "1"}
		if ttl > 0 {
			newEntry.expiresAt = now.Add(ttl)
		}
		s.entries[key] = newEntry
		return 1, nil
	}

	count, _ := strconv.ParseInt(entry.value, 10, 64)
	count++
	s.entries[key] = memoryEntry{value: strconv.FormatInt(count, 10), expiresAt: entry.expiresAt}
	return count, nil
}

func (s *MemoryStore) TTL(_ context.Context, key string) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		return 0, ErrNotFound
	}
	if entry.expiresAt.IsZero() {
		return -1 * time.Second, nil
	}
	remaining := time.Until(entry.expiresAt)
	if remaining <= 0 {
		delete(s.entries, key)
		return 0, ErrNotFound
	}
	return remaining, nil
}
