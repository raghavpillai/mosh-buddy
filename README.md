# mosh-buddy

Run commands on your local machine from inside a remote mosh session.

You're SSHed into a server, and you want to open a URL in your local browser. Or copy something to your local clipboard. Or fire off a desktop notification when a build finishes. Normally you can't do any of that because mosh doesn't forward anything back to you.

mosh-buddy fixes this. It sets up an SSH reverse tunnel alongside your mosh session and uses it to relay commands back home.

## How it works

```
[remote server]                        [local machine]
  mb open https://...
    |
    v
  server daemon ---SSH tunnel---> client daemon
                                    |
                                    v
                                  xdg-open https://...
```

Two daemons, one on each end. The server daemon runs on the remote machine and accepts commands over a Unix socket. The client daemon runs locally and executes them. They talk through an SSH reverse tunnel that `mb connect` sets up automatically.

Every command is HMAC-SHA256 signed with a per-session key, checked against an allowlist, and timestamped to prevent replay. If the tunnel goes down, commands get queued to disk and drain automatically when it comes back.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/raghavpillai/mosh-buddy/main/install.sh | sh
```

Or build from source:

```sh
go build -o mb ./cmd/mb
```

Single static binary, zero external dependencies. Install it on both machines (local and remote).

To make `mosh` automatically use mosh-buddy:

```sh
# add to your .bashrc / .zshrc
alias mosh='mb connect'
```

## Usage

### Start a session

```sh
# on your local machine
mb connect user@server
```

This does everything: starts the local client daemon, generates a session with HMAC keys, registers it on the remote, sets up the reverse tunnel, and launches mosh. When you exit mosh, it cleans up.

### Run commands from the remote

Once you're in the mosh session, `mb` commands execute on your local machine:

```sh
# open a URL in your local browser
mb open https://github.com/raghavpillai/mosh-buddy

# copy to local clipboard
echo "some text" | mb pbcopy

# desktop notification
mb notify-send "deploy finished"
```

### Placeholders

Commands can use `{MB_*}` placeholders that get expanded before execution. This is how you open remote directories in local editors.

| Placeholder | Value |
|---|---|
| `{MB_HOST}` | Remote hostname (from `mb connect` target) |
| `{MB_USER}` | Remote username (from `mb connect` target) |
| `{MB_CWD}` | Current working directory on remote |
| `{MB_SESSION}` | Session UUID |

```sh
# open current remote directory in local Zed
mb zed ssh://{MB_USER}@{MB_HOST}{MB_CWD}

# open in local VS Code
mb code --remote ssh-remote+{MB_HOST} {MB_CWD}

# open in local Cursor
mb cursor --remote ssh-remote+{MB_HOST} {MB_CWD}
```

Any `{...}` placeholder that doesn't start with `MB_` is rejected with an error. Empty placeholders tell you you're not in a session.

### Check status

```sh
mb status
```

Shows whether the daemons are running and lists active sessions.

## Security

Commands are gated by an allowlist in `~/.mb/config.json`:

```json
{
  "allow": ["open", "xdg-open", "pbcopy", "pbpaste", "xclip", "xsel", "notify-send"],
  "deny": ["rm", "sudo", "sh", "bash", "zsh", "curl", "wget"],
  "prompt_unknown": true
}
```

- Allowed commands execute immediately
- Denied commands are rejected
- Unknown commands are rejected (v1 behavior; v2 will add a desktop prompt)

Session IDs are validated as UUIDs to prevent path traversal. HMAC keys are passed over stdin (not visible in `ps`). Timestamps are checked within a 5-minute window.

## Project structure

```
cmd/mb/main.go              CLI entry point
internal/
  protocol/message.go       Wire protocol (length-prefixed JSON)
  security/auth.go          HMAC-SHA256 signing and verification
  queue/queue.go            Disk-backed message queue
  client/daemon.go          Local daemon that executes commands
  client/connect.go         Session orchestration
  server/daemon.go          Remote daemon that routes commands
  server/register.go        Session registration
  integration_test.go       End-to-end tests
```

## Queue behavior

If the tunnel drops (laptop closes, network blip, whatever), commands don't disappear. They get written to `~/.mb/queue/<session-id>/` as JSON files. The server daemon checks every 5 seconds and forwards them once the tunnel reconnects. Files are claimed atomically via rename to prevent duplicate delivery.

## License

MIT
