package client

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/raghavpillai/mosh-buddy/internal/protocol"
	"github.com/raghavpillai/mosh-buddy/internal/security"
)

type ClientDaemon struct {
	port     int
	listener net.Listener
	mbDir    string
}

func NewClientDaemon(port int) *ClientDaemon {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot determine home directory: %v", err)
	}
	mbDir := filepath.Join(homeDir, ".mb")
	return &ClientDaemon{
		port:  port,
		mbDir: mbDir,
	}
}


func (d *ClientDaemon) Run(ctx context.Context) error {
	addr := fmt.Sprintf("127.0.0.1:%d", d.port)
	var err error
	d.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Printf("client daemon listening on %s", addr)

	go func() {
		<-ctx.Done()
		d.listener.Close()
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

func (d *ClientDaemon) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	msg, err := protocol.Decode(conn)
	if err != nil {
		log.Printf("decode error: %v", err)
		sendError(conn, "", fmt.Sprintf("decode: %v", err))
		return
	}

	if msg.Type != "exec" {
		sendError(conn, msg.SessionID, "client daemon only handles exec messages")
		return
	}

	if err := protocol.ValidateSessionID(msg.SessionID); err != nil {
		log.Printf("invalid session ID: %v", err)
		sendError(conn, msg.SessionID, err.Error())
		return
	}

	key, err := d.loadSessionKey(msg.SessionID)
	if err != nil {
		log.Printf("session %s: key load error: %v", msg.SessionID, err)
		sendError(conn, msg.SessionID, fmt.Sprintf("load key: %v", err))
		return
	}

	if !security.Verify(key, msg) {
		log.Printf("session %s: HMAC verification failed for command %q", msg.SessionID, msg.Command)
		sendError(conn, msg.SessionID, "HMAC verification failed")
		return
	}

	if !security.ValidateTimestamp(msg.Timestamp, 5*time.Minute) {
		log.Printf("session %s: stale timestamp for command %q", msg.SessionID, msg.Command)
		sendError(conn, msg.SessionID, "stale timestamp")
		return
	}

	log.Printf("session %s: executing %s %s", msg.SessionID, msg.Command, strings.Join(msg.Args, " "))
	cmd := exec.Command(msg.Command, msg.Args...)
	if len(msg.Stdin) > 0 {
		cmd.Stdin = strings.NewReader(string(msg.Stdin))
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("session %s: command error: %v, output: %s", msg.SessionID, err, output)
		sendError(conn, msg.SessionID, fmt.Sprintf("exec: %v: %s", err, output))
		return
	}

	log.Printf("session %s: command succeeded", msg.SessionID)
	_ = protocol.Encode(conn, &protocol.Message{
		Type:      "ack",
		SessionID: msg.SessionID,
		Output:    output,
	})
}

func (d *ClientDaemon) loadSessionKey(sessionID string) ([]byte, error) {
	path := filepath.Join(d.mbDir, "sessions", sessionID, "key")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return security.KeyFromHex(strings.TrimSpace(string(data)))
}


func sendError(conn net.Conn, sessionID string, errMsg string) {
	_ = protocol.Encode(conn, &protocol.Message{
		Type:      "error",
		SessionID: sessionID,
		Error:     errMsg,
	})
}
