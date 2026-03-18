# MUDlark Proxy Server

A lightweight proxy server for the [MUDlark](https://testflight.apple.com/join/w8BUhwcQ) iOS client. It keeps a persistent TCP connection to your MUD server running 24/7, so you can close your phone, switch Wi-Fi, or let the app go to sleep — then reconnect and pick up right where you left off with everything you missed.

Works on **Linux**, **macOS**, and **Windows**.

---

## What You Need

| Requirement | Why |
|---|---|
| A computer that stays on | The proxy needs to run continuously so your MUD connection stays alive |
| An internet connection | So your phone can reach the proxy, and the proxy can reach the MUD |

That's it. Everything else is installed in the steps below.

---

## Setup (Step by Step)

### Step 1: Install Go

Go is the programming language the proxy is written in. You need it to build the server.

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install -y golang
```

**Linux (other) / manual install:**
```bash
# Download the latest Go (check https://go.dev/dl/ for newest version)
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz

# Add Go to your PATH (add this line to ~/.bashrc or ~/.zshrc to make it permanent)
export PATH=$PATH:/usr/local/go/bin
```

**macOS:**
```bash
# Option A: Homebrew
brew install go

# Option B: Download the installer from https://go.dev/dl/
# Run the .pkg file and follow the prompts
```

**Windows:**
1. Go to https://go.dev/dl/
2. Download the `.msi` installer (e.g. `go1.24.1.windows-amd64.msi`)
3. Run the installer — accept all defaults
4. Open a **new** Command Prompt or PowerShell window (so it picks up the PATH change)

**Verify Go is installed:**
```bash
go version
# Should print something like: go version go1.24.1 linux/amd64
```

---

### Step 2: Download the Proxy

```bash
git clone https://github.com/mudlark-app/mudlark-proxy.git
cd mudlark-proxy
```

Or download the ZIP from GitHub and extract it.

---

### Step 3: Build

**Linux / macOS:**
```bash
go build -o mudlark-proxy ./cmd/server
```

**Windows (Command Prompt):**
```cmd
go build -o mudlark-proxy.exe ./cmd/server
```

---

### Step 4: Generate a JWT Secret

The proxy uses a secret key to create secure login tokens. You need to generate a random one.

**Linux / macOS:**
```bash
openssl rand -base64 32
```
This prints a random string like `K7xB3pQ9mN2vR5wT8yA1cE4fG6hJ0kL3nP7qS9uW2x=`. Copy it — you'll use it in the next step.

**Windows (PowerShell):**
```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }) -as [byte[]])
```

**Or just make one up** — any long random string works (at least 32 characters). Example:
```
myS3cretK3y-make-this-something-random-and-long
```

---

### Step 5: Configure

Open `config.yaml` in any text editor. The only thing you **must** change is the JWT secret:

```yaml
auth:
  jwt_secret: "paste-your-secret-here"   # The random string from Step 4
```

Everything else works with the defaults. The proxy will start on port **8443** in plain WebSocket mode (no TLS), which is fine for local network use.

**Optional settings you might want to change:**

| Setting | Default | What it does |
|---|---|---|
| `server.address` | `:8443` | Port number — change the `8443` to whatever you want |
| `mud.idle_timeout` | `60m` | How long the MUD connection stays alive with no client connected |
| `buffer.capacity` | `2000` | How many lines of MUD output to save for replay |

---

### Step 6: Run

**Linux / macOS:**
```bash
# Set the secret and run (if you didn't put the secret in config.yaml)
JWT_SECRET="paste-your-secret-here" ./mudlark-proxy

# Or if you put it in config.yaml, just:
./mudlark-proxy
```

**Windows (Command Prompt):**
```cmd
set JWT_SECRET=paste-your-secret-here
mudlark-proxy.exe
```

**Windows (PowerShell):**
```powershell
$env:JWT_SECRET = "paste-your-secret-here"
.\mudlark-proxy.exe
```

You should see:
```
MUDlark proxy server started on :8443
```

After building the .exe once you should just be able to double click it the next time. 

---

### Step 7: Connect Your MUDlark Client

In the MUDlark app, set the proxy address to:

```
ws://YOUR-COMPUTER-IP:8443/ws
```

Replace `YOUR-COMPUTER-IP` with your computer's local IP address.

**To find your IP:**
- **Linux:** `hostname -I` (first address)
- **macOS:** `ipconfig getifaddr en0`
- **Windows:** `ipconfig` (look for "IPv4 Address" under your active adapter)

If connecting outside your network, you may need to handle port forwarding at your router/firewall.

Due to the innumerable routers out there I am unable to provide assistance here. A good place to start is googling your router name and looking for port forwarding or NAT/gaming etc. On linux you will also need to probably edit firewall rules (ufw command).

---

### Step 8: Verify It Works

Open a browser or terminal and check the health endpoint:

```bash
curl http://localhost:8443/healthz
```

You should see:
```json
{"status":"ok","sessions":0}
```

---

## Running as a Background Service (Optional)

### Linux (systemd)

This keeps the proxy running even after you log out or reboot.

```bash
# 1. Create a system user for the proxy
sudo useradd -r -s /usr/sbin/nologin mudlark

# 2. Copy files to /opt
sudo mkdir -p /opt/mudlark-proxy/data
sudo cp mudlark-proxy config.yaml /opt/mudlark-proxy/
sudo chown -R mudlark:mudlark /opt/mudlark-proxy

# 3. Store your JWT secret securely
sudo mkdir -p /etc/mudlark-proxy
echo "JWT_SECRET=paste-your-secret-here" | sudo tee /etc/mudlark-proxy/env
sudo chmod 600 /etc/mudlark-proxy/env

# 4. Install and start the service
sudo cp mudlark-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mudlark-proxy

# 5. Check it's running
sudo systemctl status mudlark-proxy
```

Edit the paths in `mudlark-proxy.service` if you installed somewhere other than `/opt/mudlark-proxy/`.

### Windows (Start on Login)

The simplest approach is to create a batch file and add it to your Startup folder:

1. Create a file called `start-mudlark.bat`:
   ```bat
   @echo off
   set JWT_SECRET=paste-your-secret-here
   cd /d "C:\path\to\mudlark-proxy"
   mudlark-proxy.exe
   ```

2. Press `Win+R`, type `shell:startup`, press Enter
3. Copy `start-mudlark.bat` into the folder that opens

The proxy will start automatically when you log in.

### macOS (launchd)

Create `~/Library/LaunchAgents/com.mudlark.proxy.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mudlark.proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/mudlark-proxy</string>
        <string>-config</string>
        <string>/path/to/config.yaml</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>JWT_SECRET</key>
        <string>paste-your-secret-here</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Then: `launchctl load ~/Library/LaunchAgents/com.mudlark.proxy.plist`

---

## TLS / HTTPS (Optional, Recommended for Internet-Facing Servers)

If the proxy is only on your local network, plain WebSocket (`ws://`) is fine. If you're exposing it to the internet, enable TLS:

```yaml
server:
  address: ":8443"
  tls_cert_file: "/path/to/fullchain.pem"
  tls_key_file: "/path/to/privkey.pem"
```

You can get free TLS certificates from [Let's Encrypt](https://letsencrypt.org/) using [Certbot](https://certbot.eff.org/), or use a reverse proxy like [Caddy](https://caddyserver.com/) which handles certificates automatically.

---

## Graceful Restart (Linux Only)

Warns all connected clients before shutting down for an update:

```bash
sudo ./scripts/graceful-restart.sh                     # 15 minute countdown
sudo RESTART_DELAY=5m ./scripts/graceful-restart.sh     # 5 minute countdown
```

---

## Configuration Reference

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `server` | `address` | `:8443` | Listen address (`:PORT` or `IP:PORT`) |
| `server` | `tls_cert_file` | `""` | TLS certificate — leave empty for plain WS |
| `server` | `tls_key_file` | `""` | TLS private key — leave empty for plain WS |
| `auth` | `jwt_secret` | `""` | Signing secret (prefer `JWT_SECRET` env var) |
| `auth` | `jwt_algorithm` | `HS256` | `HS256` or `RS256` |
| `auth` | `allowed_origins` | `[]` | WebSocket origin allowlist (empty = allow all) |
| `auth` | `user_store_path` | `data/users.json` | User registration file |
| `buffer` | `capacity` | `2000` | Ring buffer line count |
| `mud` | `connect_timeout` | `10s` | MUD TCP connect timeout |
| `mud` | `read_timeout` | `5m` | MUD socket read timeout |
| `mud` | `idle_timeout` | `60m` | Session lifetime without clients |
| `mud` | `line_ending` | `\n` | Line ending sent to MUD (`\n` or `\r\n`) |

---

## Architecture

```
mudlark-proxy/
├── cmd/server/
│   ├── main.go               # Entry point
│   ├── signal_unix.go        # Unix signal handling (SIGUSR1)
│   └── signal_windows.go     # Windows signal handling
├── internal/
│   ├── auth/jwt.go           # JWT validation
│   ├── buffer/ringbuffer.go  # Circular buffer for MUD output
│   ├── config/config.go      # Configuration loading
│   ├── server/
│   │   ├── server.go         # HTTP/WebSocket server
│   │   ├── websocket.go      # WebSocket message handlers
│   │   └── auth_handlers.go  # Registration & auth endpoints
│   ├── session/
│   │   ├── session.go        # MUD TCP session + telnet handling
│   │   └── manager.go        # Session lifecycle & cleanup
│   └── userstore/store.go    # User registration persistence
├── config.yaml               # Server configuration
└── mudlark-proxy.service     # systemd unit (Linux only)
```

## Protocol

See [PROXY_CLIENT_PROTOCOL.md](outline/PROXY_CLIENT_PROTOCOL.md) for the full client–server protocol specification.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `go: command not found` | Go isn't installed or not in your PATH — revisit Step 1 |
| Connection refused | Is the proxy running? Is the port right? Is your firewall blocking it? |
| JWT validation failed | Make sure `JWT_SECRET` matches between server and client. If you've used a different server before, reset authentication in your client. Settings > Proxy Mode > Reset Authentication |
| "Session belongs to different user" | Session ownership conflict — different user trying to use same session ID |
| MUD connection hangs | Check the MUD host/port are correct: `telnet host port` |

**Viewing logs:**

Linux (systemd): `sudo journalctl -u mudlark-proxy -f`

Windows / macOS / foreground: logs print to the terminal window.

Logs are very basic/limited by design. You will only see connects and disonnects basically.

---

## License

MIT License — see LICENSE file for details.
