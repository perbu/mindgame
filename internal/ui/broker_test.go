package ui

import (
	"testing"
	"time"

	"github.com/perbu/mindgame/internal/db"
)

func TestBrokerPublishSubscribe(t *testing.T) {
	b := NewBroker()

	ch, unsub := b.Subscribe()
	defer unsub()

	entry := &db.AuditEntry{ID: 1, Method: "GET", Action: "ALLOW"}
	b.Publish(entry)

	select {
	case got := <-ch:
		if got.ID != 1 {
			t.Errorf("ID = %d, want 1", got.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for entry")
	}
}

func TestBrokerMultipleSubscribers(t *testing.T) {
	b := NewBroker()

	ch1, unsub1 := b.Subscribe()
	defer unsub1()
	ch2, unsub2 := b.Subscribe()
	defer unsub2()

	entry := &db.AuditEntry{ID: 42}
	b.Publish(entry)

	for i, ch := range []<-chan *db.AuditEntry{ch1, ch2} {
		select {
		case got := <-ch:
			if got.ID != 42 {
				t.Errorf("subscriber %d: ID = %d, want 42", i, got.ID)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timeout", i)
		}
	}
}

func TestBrokerUnsubscribe(t *testing.T) {
	b := NewBroker()

	ch, unsub := b.Subscribe()
	unsub()

	b.Publish(&db.AuditEntry{ID: 1})

	select {
	case <-ch:
		t.Fatal("should not receive after unsubscribe")
	case <-time.After(50 * time.Millisecond):
		// Expected — no delivery.
	}
}

func TestBrokerSlowSubscriberDoesNotBlock(t *testing.T) {
	b := NewBroker()

	// Subscribe but never read.
	_, unsub := b.Subscribe()
	defer unsub()

	// Fill the buffer (64) and then some.
	for i := range 100 {
		b.Publish(&db.AuditEntry{ID: int64(i)})
	}
	// If we get here without blocking, test passes.
}
