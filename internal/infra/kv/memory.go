package kv

import (
	"context"
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

func (s *MemoryStore) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	entry, ok := s.entries[key]
	created := !ok || (!entry.expiresAt.IsZero() && now.After(entry.expiresAt))
	if created {
		newEntry := memoryEntry{value: "1"}
		if ttl > 0 {
			newEntry.expiresAt = now.Add(ttl)
		}
		s.entries[key] = newEntry
		return 1, nil
	}

	count := parseInt64(entry.value) + 1
	if !entry.expiresAt.IsZero() {
		// Keep the original expiry; TTL is only set on creation.
		s.entries[key] = memoryEntry{value: itoa(count), expiresAt: entry.expiresAt}
	} else {
		s.entries[key] = memoryEntry{value: itoa(count)}
	}
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

func parseInt64(s string) int64 {
	var n int64
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		return -n
	}
	return n
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
