# PocketPC

> Control your computer from your phone — anywhere on the same network.

A lightweight, self-hosted PWA that turns your iPhone into a remote control for your computer. No app store needed — just open a URL in Safari and add it to your home screen.

## Features

- **Real-time Dashboard** — CPU, memory, disk, GPU, network stats with live updates
- **Remote Terminal** — Run shell commands from your phone
- **File Manager** — Browse, view, and download files
- **Process Manager** — Monitor and kill processes
- **Multi-user Auth** — Admin/user roles, invite codes, registration control
- **Quick Actions** — Shutdown, sleep, cancel shutdown (admin only)
- **PWA** — Add to home screen for full-screen native app experience
- **iOS Optimized** — Safe area support, haptic-feel UI, light theme

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/PocketPC.git
cd PocketPC
./start.sh
```

That's it. The script auto-creates a virtualenv, installs dependencies, generates icons, and starts the server.

Or manually:

```bash
pip install -r requirements.txt
python generate_icons.py
python server.py
```

## Usage

### 1. Start the server

```bash
./start.sh
```

You'll see:

```
=======================================================
  PocketPC Server
=======================================================
  Local:   http://localhost:8765
  Network: http://192.168.x.x:8765
=======================================================
```

### 2. Open on your iPhone

Open the **Network** URL in Safari (phone and computer must be on the same network).

### 3. Create admin account

First visit shows a setup screen. Create your admin username and password.

### 4. Add to home screen (optional)

In Safari: **Share** → **Add to Home Screen** → looks and feels like a native app.

## Multi-user

### Invite Code (recommended)

1. Admin: **Settings** → generate an **Invite Code**
2. Share the code with others
3. They open your server URL → **Register** → enter the code

### Open Registration

Admin can enable **"Allow anyone to register"** in Settings — no code needed.

## Screenshots

| Dashboard | Terminal | Files |
|:-:|:-:|:-:|
| Real-time system stats | Remote shell access | Browse & download files |

## Architecture

```
PocketPC/
├── server.py            # FastAPI backend + auth + WebSocket
├── start.sh             # One-click launcher
├── requirements.txt     # Python dependencies
├── generate_icons.py    # PWA icon generator
├── data/                # Auto-created at runtime
│   ├── users.json       # User accounts (hashed passwords)
│   ├── sessions.json    # Active sessions
│   └── config.json      # Server config
└── static/
    ├── index.html       # PWA frontend
    ├── manifest.json    # PWA manifest
    ├── sw.js            # Service worker
    └── icons/           # App icons
```

## Security

- Passwords hashed with **PBKDF2-SHA256** + random salt
- Token-based sessions (7-day expiry)
- All API endpoints require authentication
- WebSocket connections require valid token
- Dangerous actions (shutdown/sleep) are admin-only
- **Use on trusted networks only** — traffic is HTTP (unencrypted)

## Requirements

- Python 3.8+
- Works on Linux, macOS, Windows
- iPhone with Safari (or any modern browser)

## License

MIT
