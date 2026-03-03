package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/raghavpillai/mosh-buddy/internal/protocol"
)

var enqueueCounter uint64

type Queue struct {
	baseDir string
}

func NewQueue(baseDir string) *Queue {
	return &Queue{baseDir: baseDir}
}

func (q *Queue) sessionDir(sessionID string) string {
	return filepath.Join(q.baseDir, sessionID)
}

func (q *Queue) Enqueue(sessionID string, msg *protocol.Message) error {
	dir := q.sessionDir(sessionID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create queue dir: %w", err)
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	seq := atomic.AddUint64(&enqueueCounter, 1)
	filename := fmt.Sprintf("%d-%d.json", time.Now().UnixNano(), seq)
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write queue file: %w", err)
	}
	return nil
}

func (q *Queue) Drain(sessionID string) ([]*protocol.Message, error) {
	dir := q.sessionDir(sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read queue dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var messages []*protocol.Message
	for _, name := range names {
		path := filepath.Join(dir, name)
		// Atomic rename prevents duplicate drain
		claimedPath := path + ".draining"
		if err := os.Rename(path, claimedPath); err != nil {
			continue // another goroutine already claimed it
		}
		data, err := os.ReadFile(claimedPath)
		if err != nil {
			return messages, fmt.Errorf("read queue file %s: %w", name, err)
		}
		var msg protocol.Message
		if err := json.Unmarshal(data, &msg); err != nil {
			os.Remove(claimedPath)
			return messages, fmt.Errorf("unmarshal queue file %s: %w", name, err)
		}
		messages = append(messages, &msg)
		os.Remove(claimedPath)
	}
	return messages, nil
}

func (q *Queue) Pending(sessionID string) (int, error) {
	dir := q.sessionDir(sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read queue dir: %w", err)
	}
	count := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			count++
		}
	}
	return count, nil
}

func (q *Queue) EnqueueAt(sessionID string, msg *protocol.Message, nanos int64) error {
	dir := q.sessionDir(sessionID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create queue dir: %w", err)
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	filename := strconv.FormatInt(nanos, 10) + ".json"
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write queue file: %w", err)
	}
	return nil
}
