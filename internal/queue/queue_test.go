package queue

import (
	"os"
	"sync"
	"testing"

	"github.com/raghavpillai/mosh-buddy/internal/protocol"
)

func tempQueue(t *testing.T) *Queue {
	t.Helper()
	dir, err := os.MkdirTemp("", "mb-queue-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return NewQueue(dir)
}

func TestEnqueueDrain(t *testing.T) {
	q := tempQueue(t)

	for i := 0; i < 3; i++ {
		msg := &protocol.Message{
			Type:      "exec",
			SessionID: "sess-1",
			Command:   "open",
			Args:      []string{string(rune('a' + i))},
			Timestamp: int64(i),
		}
		// Use explicit timestamps to ensure ordering
		if err := q.EnqueueAt("sess-1", msg, int64(i+1)*1000000); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}

	msgs, err := q.Drain("sess-1")
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("Drain: got %d messages, want 3", len(msgs))
	}
	for i, msg := range msgs {
		expected := string(rune('a' + i))
		if msg.Args[0] != expected {
			t.Errorf("msg %d args: got %q, want %q", i, msg.Args[0], expected)
		}
	}
}

func TestDrainEmpty(t *testing.T) {
	q := tempQueue(t)
	msgs, err := q.Drain("nonexistent")
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("Drain empty: got %d messages, want 0", len(msgs))
	}
}

func TestSessionIsolation(t *testing.T) {
	q := tempQueue(t)

	msgA := &protocol.Message{Type: "exec", SessionID: "a", Command: "open", Args: []string{"a"}}
	msgB := &protocol.Message{Type: "exec", SessionID: "b", Command: "open", Args: []string{"b"}}
	if err := q.Enqueue("a", msgA); err != nil {
		t.Fatalf("Enqueue a: %v", err)
	}
	if err := q.Enqueue("b", msgB); err != nil {
		t.Fatalf("Enqueue b: %v", err)
	}

	msgsA, _ := q.Drain("a")
	if len(msgsA) != 1 || msgsA[0].Args[0] != "a" {
		t.Errorf("session a: got %v", msgsA)
	}
	msgsB, _ := q.Drain("b")
	if len(msgsB) != 1 || msgsB[0].Args[0] != "b" {
		t.Errorf("session b: got %v", msgsB)
	}
}

func TestDrainCleansUp(t *testing.T) {
	q := tempQueue(t)
	msg := &protocol.Message{Type: "exec", SessionID: "s", Command: "open"}
	if err := q.Enqueue("s", msg); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := q.Drain("s"); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	count, _ := q.Pending("s")
	if count != 0 {
		t.Errorf("after drain, pending = %d, want 0", count)
	}
}

func TestPending(t *testing.T) {
	q := tempQueue(t)
	for i := 0; i < 5; i++ {
		msg := &protocol.Message{Type: "exec", SessionID: "s", Command: "open"}
		if err := q.Enqueue("s", msg); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}
	count, err := q.Pending("s")
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if count != 5 {
		t.Errorf("Pending: got %d, want 5", count)
	}
}

func TestConcurrentEnqueue(t *testing.T) {
	q := tempQueue(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := &protocol.Message{Type: "exec", SessionID: "s", Command: "open", Args: []string{string(rune('a' + i))}}
			_ = q.Enqueue("s", msg)
		}(i)
	}
	wg.Wait()

	count, _ := q.Pending("s")
	if count != 20 {
		t.Errorf("concurrent enqueue: pending = %d, want 20", count)
	}
}
