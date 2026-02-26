package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/raghav/mosh-buddy/internal/client"
	"github.com/raghav/mosh-buddy/internal/protocol"
	"github.com/raghav/mosh-buddy/internal/server"
	"github.com/raghav/mosh-buddy/internal/updater"
)

var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Resolve mbDir once for update checks
	mbDir := ""
	if homeDir, err := os.UserHomeDir(); err == nil {
		mbDir = filepath.Join(homeDir, ".mb")
	}

	var err error
	switch os.Args[1] {
	case "connect":
		done := updater.CheckInBackground(version, mbDir)
		err = client.Connect(os.Args[2:])
		updater.PrintUpdateNotice(version, mbDir, done)
	case "client-daemon":
		err = runClientDaemon(os.Args[2:])
	case "server-daemon":
		err = runServerDaemon(os.Args[2:])
	case "_register":
		err = server.Register(os.Args[2:])
	case "_deregister":
		err = server.Deregister(os.Args[2:])
	case "status":
		done := updater.CheckInBackground(version, mbDir)
		err = handleStatus()
		updater.PrintUpdateNotice(version, mbDir, done)
	case "update":
		err = updater.Update(version)
	case "version", "--version", "-v":
		fmt.Printf("mb %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		err = remoteExec(os.Args[1], os.Args[2:])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runClientDaemon(args []string) error {
	fs := flag.NewFlagSet("client-daemon", flag.ExitOnError)
	port := fs.Int("port", 4444, "port to listen on")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	daemon := client.NewClientDaemon(*port)
	return daemon.Run(ctx)
}

func runServerDaemon(args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	socketPath := filepath.Join(homeDir, ".mb", "mb.sock")

	// Ensure directories exist with correct permissions
	for _, dir := range []string{
		filepath.Join(homeDir, ".mb"),
		filepath.Join(homeDir, ".mb", "sessions"),
		filepath.Join(homeDir, ".mb", "queue"),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	daemon := server.NewServerDaemon(socketPath)
	return daemon.Run(ctx)
}

func remoteExec(command string, args []string) error {
	sessionID := os.Getenv("MB_SESSION")
	if sessionID == "" {
		return fmt.Errorf("MB_SESSION not set. Are you inside an mb connect session?")
	}

	// Read stdin if piped
	var stdin []byte
	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeCharDevice == 0 {
		var err error
		stdin, err = io.ReadAll(io.LimitReader(os.Stdin, protocol.MaxMessageSize))
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
	}

	// Connect to server daemon
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	socketPath := filepath.Join(homeDir, ".mb", "mb.sock")
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("connect to server daemon: %w (is mb server-daemon running?)", err)
	}
	defer conn.Close()

	// Expand {MB_*} placeholders in command and args
	command, err = expandPlaceholders(command)
	if err != nil {
		return err
	}
	for i, arg := range args {
		args[i], err = expandPlaceholders(arg)
		if err != nil {
			return err
		}
	}

	// Build and send exec message (unsigned — server daemon will sign it)
	msg := &protocol.Message{
		Type:      "exec",
		SessionID: sessionID,
		Command:   command,
		Args:      args,
		Stdin:     stdin,
	}
	if err := protocol.Encode(conn, msg); err != nil {
		return fmt.Errorf("send command: %w", err)
	}

	// Read response
	resp, err := protocol.Decode(conn)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Type == "error" {
		return fmt.Errorf("%s", resp.Error)
	}
	if len(resp.Output) > 0 {
		os.Stdout.Write(resp.Output)
	}

	return nil
}

func handleStatus() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	// Check for server daemon (attempt to connect, not just stat the file)
	socketPath := filepath.Join(homeDir, ".mb", "mb.sock")
	if sconn, serr := net.Dial("unix", socketPath); serr == nil {
		sconn.Close()
		fmt.Println("Server daemon: running")
	} else {
		fmt.Println("Server daemon: not running")
	}

	// Check for client daemon
	conn, err := net.Dial("tcp", "127.0.0.1:4444")
	if err == nil {
		conn.Close()
		fmt.Println("Client daemon: running on port 4444")
	} else {
		fmt.Println("Client daemon: not running")
	}

	// List sessions
	sessDir := filepath.Join(homeDir, ".mb", "sessions")
	entries, err := os.ReadDir(sessDir)
	if err == nil && len(entries) > 0 {
		fmt.Printf("\nActive sessions:\n")
		for _, e := range entries {
			if e.IsDir() {
				fmt.Printf("  - %s\n", e.Name())
			}
		}
	} else {
		fmt.Println("\nNo active sessions")
	}

	return nil
}

var placeholderRe = regexp.MustCompile(`\{[^}]+\}`)

// expandPlaceholders replaces {MB_*} placeholders with their environment values.
// Any {…} placeholder that doesn't start with MB_ is an error.
func expandPlaceholders(s string) (string, error) {
	var expandErr error
	result := placeholderRe.ReplaceAllStringFunc(s, func(match string) string {
		name := match[1 : len(match)-1] // strip { }
		if !strings.HasPrefix(name, "MB_") {
			expandErr = fmt.Errorf("unknown placeholder %s (only {MB_*} placeholders are supported)", match)
			return match
		}
		val := os.Getenv(name)
		// MB_CWD falls back to PWD
		if val == "" && name == "MB_CWD" {
			val, _ = os.Getwd()
		}
		if val == "" {
			expandErr = fmt.Errorf("placeholder %s is empty (are you inside an mb connect session?)", match)
			return match
		}
		return val
	})
	if expandErr != nil {
		return "", expandErr
	}
	return result, nil
}

func printUsage() {
	fmt.Printf(`mosh-buddy (mb) %s — side-channel for mosh sessions

Usage:
  mb connect user@host       Start a mosh session with side-channel
  mb client-daemon [--port]  Start the client daemon (usually auto-started)
  mb server-daemon           Start the server daemon
  mb status                  Show daemon and session status
  mb update                  Update mb to the latest version
  mb version                 Show version
  mb <command> [args...]     Execute command on local machine (from remote)

Placeholders (expanded from environment):
  {MB_HOST}    Remote hostname (from mb connect target)
  {MB_USER}    Remote username (from mb connect target)
  {MB_CWD}     Current working directory on remote
  {MB_SESSION} Session UUID

Examples (on remote, inside mb connect session):
  mb open https://example.com                      Open URL in local browser
  echo "text" | mb pbcopy                          Copy to local clipboard
  mb notify-send "build finished"                  Local desktop notification
  mb zed ssh://{MB_USER}@{MB_HOST}{MB_CWD}          Open remote dir in local Zed
  mb code --remote ssh-remote+{MB_HOST} {MB_CWD}   Open remote dir in local VS Code
`, version)
}
