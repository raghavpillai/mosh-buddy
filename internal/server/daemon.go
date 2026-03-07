package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/raghavpillai/mosh-buddy/internal/protocol"
	"github.com/raghavpillai/mosh-buddy/internal/queue"
	"github.com/raghavpillai/mosh-buddy/internal/security"
)

type SessionInfo struct {
	Port int
	Key  []byte
}

type ServerDaemon struct {
	socketPath string
	mbDir      string
	listener   net.Listener
	sessions   map[string]*SessionInfo
	mu         sync.RWMutex
	queue      *queue.Queue
}

func NewServerDaemon(socketPath string) *ServerDaemon {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot determine home directory: %v", err)
	}
	mbDir := filepath.Join(homeDir, ".mb")
	return &ServerDaemon{
		socketPath: socketPath,
		mbDir:      mbDir,
		sessions:   make(map[string]*SessionInfo),
		queue:      queue.NewQueue(filepath.Join(mbDir, "queue")),
	}
}

// NewServerDaemonWithDir creates a server daemon with a custom base directory (for testing)
func NewServerDaemonWithDir(socketPath, mbDir string) *ServerDaemon {
	return &ServerDaemon{
		socketPath: socketPath,
		mbDir:      mbDir,
		sessions:   make(map[string]*SessionInfo),
		queue:      queue.NewQueue(filepath.Join(mbDir, "queue")),
	}
}

func (d *ServerDaemon) Run(ctx context.Context) error {
	if _, err := os.Stat(d.socketPath); err == nil {
		os.Remove(d.socketPath)
	}

	socketDir := filepath.Dir(d.socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	if err := os.Chmod(socketDir, 0700); err != nil {
		return fmt.Errorf("chmod socket dir: %w", err)
	}

	var err error
	d.listener, err = net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", d.socketPath, err)
	}
	if err := os.Chmod(d.socketPath, 0600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	d.recoverSessions()

	log.Printf("server daemon listening on %s", d.socketPath)

	go d.drainLoop(ctx)

	go func() {
		<-ctx.Done()
		d.listener.Close()
		os.Remove(d.socketPath)
	}()

	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}
		go d.handleConn(conn)
	}
}

func (d *ServerDaemon) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	msg, err := protocol.Decode(conn)
	if err != nil {
		log.Printf("decode error: %v", err)
		_ = protocol.Encode(conn, &protocol.Message{Type: "error", Error: fmt.Sprintf("decode: %v", err)})
		return
	}

	switch msg.Type {
	case "register":
		d.handleRegister(conn, msg)
	case "deregister":
		d.handleDeregister(conn, msg)
	case "exec":
		d.handleExec(conn, msg)
	default:
		_ = protocol.Encode(conn, &protocol.Message{
			Type:      "error",
			SessionID: msg.SessionID,
			Error:     fmt.Sprintf("unknown message type: %s", msg.Type),
		})
	}
}

func (d *ServerDaemon) handleRegister(conn net.Conn, msg *protocol.Message) {
	if err := protocol.ValidateSessionID(msg.SessionID); err != nil {
		log.Printf("register: %v", err)
		_ = protocol.Encode(conn, &protocol.Message{Type: "error", Error: err.Error()})
		return
	}

	key, err := security.KeyFromHex(msg.Key)
	if err != nil {
		log.Printf("register: bad key: %v", err)
		_ = protocol.Encode(conn, &protocol.Message{
			Type:  "error",
			Error: fmt.Sprintf("bad key: %v", err),
		})
		return
	}

	keyDir := filepath.Join(d.mbDir, "sessions", msg.SessionID)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		log.Printf("register: mkdir error: %v", err)
		_ = protocol.Encode(conn, &protocol.Message{Type: "error", Error: fmt.Sprintf("mkdir: %v", err)})
		return
	}
	if err := os.WriteFile(filepath.Join(keyDir, "key"), []byte(msg.Key), 0600); err != nil {
		log.Printf("register: write key error: %v", err)
		_ = protocol.Encode(conn, &protocol.Message{Type: "error", Error: fmt.Sprintf("write key: %v", err)})
		return
	}

	d.mu.Lock()
	d.sessions[msg.SessionID] = &SessionInfo{
		Port: msg.Port,
		Key:  key,
	}
	d.mu.Unlock()

	log.Printf("registered session %s → port %d", msg.SessionID, msg.Port)

	_ = protocol.Encode(conn, &protocol.Message{
		Type:      "ack",
		SessionID: msg.SessionID,
	})
}

func (d *ServerDaemon) handleDeregister(conn net.Conn, msg *protocol.Message) {
	if err := protocol.ValidateSessionID(msg.SessionID); err != nil {
		log.Printf("deregister: %v", err)
		_ = protocol.Encode(conn, &protocol.Message{Type: "error", Error: err.Error()})
		return
	}

	d.mu.Lock()
	delete(d.sessions, msg.SessionID)
	d.mu.Unlock()

	keyDir := filepath.Join(d.mbDir, "sessions", msg.SessionID)
	os.RemoveAll(keyDir)

	log.Printf("deregistered session %s", msg.SessionID)

	_ = protocol.Encode(conn, &protocol.Message{
		Type:      "ack",
		SessionID: msg.SessionID,
	})
}

func (d *ServerDaemon) handleExec(conn net.Conn, msg *protocol.Message) {
	if err := protocol.ValidateSessionID(msg.SessionID); err != nil {
		_ = protocol.Encode(conn, &protocol.Message{Type: "error", Error: err.Error()})
		return
	}

	d.mu.RLock()
	session, ok := d.sessions[msg.SessionID]
	d.mu.RUnlock()

	if !ok {
		log.Printf("exec: unknown session %s", msg.SessionID)
		_ = protocol.Encode(conn, &protocol.Message{
			Type:      "error",
			SessionID: msg.SessionID,
			Error:     "unknown session",
		})
		return
	}

	if session.Port == 0 {
		log.Printf("session %s: port unknown (awaiting re-register), queuing", msg.SessionID)
		msg.Timestamp = time.Now().Unix()
		msg.HMAC = security.Sign(session.Key, msg)
		if err := d.queue.Enqueue(msg.SessionID, msg); err != nil {
			log.Printf("session %s: queue error: %v", msg.SessionID, err)
		}
		_ = protocol.Encode(conn, &protocol.Message{
			Type:      "ack",
			SessionID: msg.SessionID,
		})
		return
	}

	msg.Timestamp = time.Now().Unix()
	msg.HMAC = security.Sign(session.Key, msg)

	resp, err := d.forwardToTunnel(session.Port, msg)
	if err != nil {
		// Tunnel down — queue for later delivery
		log.Printf("session %s: tunnel unreachable (%v), queuing", msg.SessionID, err)
		if qErr := d.queue.Enqueue(msg.SessionID, msg); qErr != nil {
			log.Printf("session %s: queue error: %v", msg.SessionID, qErr)
			_ = protocol.Encode(conn, &protocol.Message{
				Type:      "error",
				SessionID: msg.SessionID,
				Error:     fmt.Sprintf("tunnel down and queue failed: %v", qErr),
			})
			return
		}
		_ = protocol.Encode(conn, &protocol.Message{
			Type:      "ack",
			SessionID: msg.SessionID,
		})
		return
	}

	_ = protocol.Encode(conn, resp)
}

func (d *ServerDaemon) forwardToTunnel(port int, msg *protocol.Message) (*protocol.Message, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := protocol.Encode(conn, msg); err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	resp, err := protocol.Decode(conn)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return resp, nil
}

func (d *ServerDaemon) drainLoop(ctx context.Context) {
	drainTicker := time.NewTicker(5 * time.Second)
	cleanTicker := time.NewTicker(5 * time.Minute)
	defer drainTicker.Stop()
	defer cleanTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-drainTicker.C:
			d.drainAll()
		case <-cleanTicker.C:
			d.cleanStale()
		}
	}
}

func (d *ServerDaemon) drainAll() {
	d.mu.RLock()
	type snapshot struct {
		Port int
		Key  []byte
	}
	sessions := make(map[string]snapshot)
	for k, v := range d.sessions {
		keyCopy := make([]byte, len(v.Key))
		copy(keyCopy, v.Key)
		sessions[k] = snapshot{Port: v.Port, Key: keyCopy}
	}
	d.mu.RUnlock()

	for sessionID, session := range sessions {
		if session.Port == 0 {
			continue
		}

		pending, _ := d.queue.Pending(sessionID)
		if pending == 0 {
			continue
		}

		msgs, err := d.queue.Drain(sessionID)
		if err != nil {
			log.Printf("drain error for session %s: %v", sessionID, err)
			continue
		}

		for i, msg := range msgs {
			msg.Timestamp = time.Now().Unix()
			msg.HMAC = security.Sign(session.Key, msg)

			if _, err := d.forwardToTunnel(session.Port, msg); err != nil {
				log.Printf("drain forward error for session %s: %v", sessionID, err)
				for j := i; j < len(msgs); j++ {
					if err := d.queue.Enqueue(sessionID, msgs[j]); err != nil {
						log.Printf("session %s: re-queue error: %v", sessionID, err)
					}
				}
				break
			}
		}
	}
}

// cleanStale removes session directories and queue entries for sessions that are
// not registered in memory and whose directory hasn't been modified in over 1 hour.
func (d *ServerDaemon) cleanStale() {
	d.mu.RLock()
	active := make(map[string]bool, len(d.sessions))
	for k := range d.sessions {
		active[k] = true
	}
	d.mu.RUnlock()

	// Clean orphaned queue directories
	d.queue.CleanOrphaned(active)

	// Clean stale session directories (not in memory, older than 1 hour)
	sessDir := filepath.Join(d.mbDir, "sessions")
	entries, err := os.ReadDir(sessDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-1 * time.Hour)
	for _, e := range entries {
		if !e.IsDir() {
			os.Remove(filepath.Join(sessDir, e.Name()))
			continue
		}
		if active[e.Name()] {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			log.Printf("cleaning stale session dir %s (last modified %s)", e.Name(), info.ModTime().Format(time.RFC3339))
			os.RemoveAll(filepath.Join(sessDir, e.Name()))
		}
	}
}

func (d *ServerDaemon) recoverSessions() {
	sessDir := filepath.Join(d.mbDir, "sessions")
	entries, err := os.ReadDir(sessDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sessionID := e.Name()
		if err := protocol.ValidateSessionID(sessionID); err != nil {
			log.Printf("recover: skipping invalid session dir %q", sessionID)
			continue
		}
		sessionDir := filepath.Join(sessDir, sessionID)
		os.Chmod(sessionDir, 0700) // enforce correct permissions
		keyPath := filepath.Join(sessionDir, "key")
		data, err := os.ReadFile(keyPath)
		if err != nil {
			continue
		}
		os.Chmod(keyPath, 0600) // enforce correct permissions
		key, err := security.KeyFromHex(strings.TrimSpace(string(data)))
		if err != nil {
			continue
		}
		// Port unknown — not routable until re-registered, but store key
		d.mu.Lock()
		d.sessions[sessionID] = &SessionInfo{Key: key}
		d.mu.Unlock()
		log.Printf("recovered session %s from disk (port unknown, awaiting re-register)", sessionID)
	}
}

// RegisterSession programmatically registers a session (for testing)
func (d *ServerDaemon) RegisterSession(sessionID string, port int, key []byte) {
	d.mu.Lock()
	d.sessions[sessionID] = &SessionInfo{Port: port, Key: key}
	d.mu.Unlock()

	keyDir := filepath.Join(d.mbDir, "sessions", sessionID)
	_ = os.MkdirAll(keyDir, 0700)
	_ = os.WriteFile(filepath.Join(keyDir, "key"), []byte(security.KeyToHex(key)), 0600)
}
