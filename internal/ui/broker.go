package ui

import (
	"sync"

	"github.com/perbu/mindgame/internal/db"
)

// Broker fans out audit entries to SSE subscribers.
type Broker struct {
	mu          sync.RWMutex
	subscribers map[uint64]chan *db.AuditEntry
	nextID      uint64
}

// NewBroker creates a new SSE broker.
func NewBroker() *Broker {
	return &Broker{
		subscribers: make(map[uint64]chan *db.AuditEntry),
	}
}

// Close closes all subscriber channels, causing SSE handlers to exit.
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, ch := range b.subscribers {
		close(ch)
		delete(b.subscribers, id)
	}
}

// Publish sends an audit entry to all subscribers. Non-blocking: slow readers miss entries.
func (b *Broker) Publish(entry *db.AuditEntry) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
}

// Subscribe returns a channel of audit entries and an unsubscribe function.
func (b *Broker) Subscribe() (<-chan *db.AuditEntry, func()) {
	ch := make(chan *db.AuditEntry, 64)
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.subscribers[id] = ch
	b.mu.Unlock()

	return ch, func() {
		b.mu.Lock()
		delete(b.subscribers, id)
		b.mu.Unlock()
	}
}
