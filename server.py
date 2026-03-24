"""
PocketPC — Control your computer from your phone.
A FastAPI-based server with multi-user auth. Deploy on any machine,
access from iPhone Safari, add to home screen for native app experience.
"""

import os
import sys
import json
import asyncio
import platform
import subprocess
import shutil
import signal
import time
import secrets
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

import psutil
from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, HTTPException,
    Query, Depends, Request, Header,
)
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="PocketPC")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ═══════════════════════════════════════════════════
#  Auth system: users stored in local JSON file
# ═══════════════════════════════════════════════════

def _hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
    return hashed, salt


def _load_users() -> dict:
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text())
    return {}


def _save_users(users: dict):
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False))


def _load_sessions() -> dict:
    if SESSIONS_FILE.exists():
        data = json.loads(SESSIONS_FILE.read_text())
        now = datetime.now().isoformat()
        data = {k: v for k, v in data.items() if v.get("expires", "") > now}
        return data
    return {}


def _save_sessions(sessions: dict):
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2))


def _create_session(username: str, role: str) -> str:
    sessions = _load_sessions()
    token = secrets.token_urlsafe(32)
    sessions[token] = {
        "username": username,
        "role": role,
        "created": datetime.now().isoformat(),
        "expires": (datetime.now() + timedelta(days=7)).isoformat(),
    }
    _save_sessions(sessions)
    return token


def _get_current_user(token: str) -> Optional[dict]:
    if not token:
        return None
    sessions = _load_sessions()
    session = sessions.get(token)
    if not session:
        return None
    if session["expires"] < datetime.now().isoformat():
        return None
    return session


def _ensure_admin_exists():
    """On first run, if no users exist, show setup instructions."""
    users = _load_users()
    if not users:
        return False
    return True


# ─── Auth dependency ───

async def require_auth(request: Request) -> dict:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        token = request.query_params.get("token", "")
    user = _get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


async def require_admin(user: dict = Depends(require_auth)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user


# ═══════════════════════════════════════════════════
#  Pages
# ═══════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def root():
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


@app.get("/manifest.json")
async def manifest():
    return FileResponse(str(BASE_DIR / "static" / "manifest.json"))


@app.get("/sw.js")
async def service_worker():
    return FileResponse(str(BASE_DIR / "static" / "sw.js"))


# ═══════════════════════════════════════════════════
#  Auth API
# ═══════════════════════════════════════════════════

@app.get("/api/auth/status")
async def auth_status():
    """Check if setup is needed (no users yet)."""
    users = _load_users()
    return {"needs_setup": len(users) == 0, "user_count": len(users)}


@app.post("/api/auth/setup")
async def setup_admin(request: Request):
    """First-time setup: create the admin account."""
    users = _load_users()
    if users:
        raise HTTPException(status_code=400, detail="Admin already exists. Use register instead.")

    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    hashed, salt = _hash_password(password)
    users[username] = {
        "password_hash": hashed,
        "salt": salt,
        "role": "admin",
        "created": datetime.now().isoformat(),
    }
    _save_users(users)
    token = _create_session(username, "admin")
    return {"token": token, "username": username, "role": "admin"}


@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()

    users = _load_users()
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    hashed, _ = _hash_password(password, user["salt"])
    if hashed != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = _create_session(username, user["role"])
    return {"token": token, "username": username, "role": user["role"]}


@app.post("/api/auth/register")
async def register(request: Request):
    """Register a new user (requires admin token or open registration if enabled)."""
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    invite_code = body.get("invite_code", "").strip()

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    users = _load_users()
    if not users:
        raise HTTPException(status_code=400, detail="Please setup admin first via /api/auth/setup")

    admin_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    admin_user = _get_current_user(admin_token)
    is_admin = admin_user and admin_user.get("role") == "admin"

    config = _load_config()
    if not is_admin and not config.get("open_registration", False):
        if not invite_code or invite_code != config.get("invite_code", ""):
            raise HTTPException(status_code=403, detail="Registration requires admin approval or valid invite code")

    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed, salt = _hash_password(password)
    users[username] = {
        "password_hash": hashed,
        "salt": salt,
        "role": "user",
        "created": datetime.now().isoformat(),
    }
    _save_users(users)
    token = _create_session(username, "user")
    return {"token": token, "username": username, "role": "user"}


@app.post("/api/auth/logout")
async def logout(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    sessions = _load_sessions()
    sessions.pop(token, None)
    _save_sessions(sessions)
    return {"status": "ok"}


@app.get("/api/auth/me")
async def me(user: dict = Depends(require_auth)):
    return {"username": user["username"], "role": user["role"]}


# ═══════════════════════════════════════════════════
#  Admin: User Management
# ═══════════════════════════════════════════════════

@app.get("/api/admin/users")
async def admin_list_users(user: dict = Depends(require_admin)):
    users = _load_users()
    return [
        {"username": u, "role": info["role"], "created": info.get("created", "")}
        for u, info in users.items()
    ]


@app.delete("/api/admin/users/{username}")
async def admin_delete_user(username: str, user: dict = Depends(require_admin)):
    if username == user["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    users = _load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    del users[username]
    _save_users(users)
    sessions = _load_sessions()
    sessions = {k: v for k, v in sessions.items() if v["username"] != username}
    _save_sessions(sessions)
    return {"status": "ok"}


@app.post("/api/admin/invite-code")
async def admin_set_invite_code(request: Request, user: dict = Depends(require_admin)):
    body = await request.json()
    config = _load_config()
    config["invite_code"] = body.get("invite_code", secrets.token_urlsafe(8))
    config["open_registration"] = body.get("open_registration", False)
    _save_config(config)
    return config


@app.get("/api/admin/config")
async def admin_get_config(user: dict = Depends(require_admin)):
    return _load_config()


# ─── Config helpers ───

CONFIG_FILE = DATA_DIR / "config.json"


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {"open_registration": False, "invite_code": ""}


def _save_config(config: dict):
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


# ═══════════════════════════════════════════════════
#  System Info (protected)
# ═══════════════════════════════════════════════════

@app.get("/api/system")
async def system_info(user: dict = Depends(require_auth)):
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot_time

    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": psutil.cpu_count(logical=True),
        "cpu_physical": psutil.cpu_count(logical=False),
        "cpu_freq_mhz": round(cpu_freq.current, 1) if cpu_freq else None,
        "memory_total_gb": round(mem.total / (1024**3), 2),
        "memory_used_gb": round(mem.used / (1024**3), 2),
        "memory_percent": mem.percent,
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_percent": disk.percent,
        "uptime": str(uptime).split(".")[0],
        "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─── Real-time System Monitor via WebSocket ───

@app.websocket("/ws/monitor")
async def monitor_ws(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    if not _get_current_user(token):
        await websocket.close(code=4001)
        return

    await websocket.accept()
    try:
        while True:
            cpu_percent = psutil.cpu_percent(interval=0.5)
            mem = psutil.virtual_memory()
            net = psutil.net_io_counters()
            temps = {}
            try:
                t = psutil.sensors_temperatures()
                if t:
                    for name, entries in t.items():
                        temps[name] = [
                            {"label": e.label or name, "current": e.current}
                            for e in entries[:3]
                        ]
            except Exception:
                pass

            await websocket.send_json({
                "cpu_percent": cpu_percent,
                "memory_percent": mem.percent,
                "memory_used_gb": round(mem.used / (1024**3), 2),
                "net_sent_mb": round(net.bytes_sent / (1024**2), 1),
                "net_recv_mb": round(net.bytes_recv / (1024**2), 1),
                "temperatures": temps,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass


# ─── Terminal via WebSocket ───

@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    if not _get_current_user(token):
        await websocket.close(code=4001)
        return

    await websocket.accept()
    cwd = str(Path.home())
    env = os.environ.copy()

    try:
        while True:
            data = await websocket.receive_json()
            cmd = data.get("command", "").strip()

            if not cmd:
                continue

            if cmd.startswith("cd "):
                target = cmd[3:].strip()
                target = os.path.expanduser(target)
                if not os.path.isabs(target):
                    target = os.path.join(cwd, target)
                target = os.path.normpath(target)
                if os.path.isdir(target):
                    cwd = target
                    await websocket.send_json({
                        "output": f"Changed directory to {cwd}\n",
                        "cwd": cwd,
                        "exit_code": 0,
                    })
                else:
                    await websocket.send_json({
                        "output": f"cd: no such directory: {target}\n",
                        "cwd": cwd,
                        "exit_code": 1,
                    })
                continue

            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    cwd=cwd,
                    env=env,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                output = stdout.decode("utf-8", errors="replace")
                await websocket.send_json({
                    "output": output if output else "(no output)\n",
                    "cwd": cwd,
                    "exit_code": proc.returncode,
                })
            except asyncio.TimeoutError:
                proc.kill()
                await websocket.send_json({
                    "output": "Command timed out (30s limit)\n",
                    "cwd": cwd,
                    "exit_code": -1,
                })
            except Exception as e:
                await websocket.send_json({
                    "output": f"Error: {str(e)}\n",
                    "cwd": cwd,
                    "exit_code": -1,
                })
    except WebSocketDisconnect:
        pass


# ─── File Browser ───

@app.get("/api/files")
async def list_files(path: str = Query(default="~"), user: dict = Depends(require_auth)):
    target = Path(os.path.expanduser(path)).resolve()
    if not target.exists():
        raise HTTPException(status_code=404, detail="Path not found")

    if target.is_file():
        try:
            content = target.read_text(errors="replace")
            return {
                "type": "file",
                "path": str(target),
                "name": target.name,
                "size": target.stat().st_size,
                "content": content[:100_000],
                "truncated": target.stat().st_size > 100_000,
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    items = []
    try:
        for entry in sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            try:
                stat = entry.stat()
                items.append({
                    "name": entry.name,
                    "path": str(entry),
                    "is_dir": entry.is_dir(),
                    "size": stat.st_size if entry.is_file() else None,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                })
            except (PermissionError, OSError):
                items.append({
                    "name": entry.name,
                    "path": str(entry),
                    "is_dir": entry.is_dir(),
                    "size": None,
                    "modified": None,
                    "error": "permission denied",
                })
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")

    return {
        "type": "directory",
        "path": str(target),
        "parent": str(target.parent) if str(target) != "/" else None,
        "items": items,
    }


@app.get("/api/files/download")
async def download_file(path: str, user: dict = Depends(require_auth)):
    target = Path(os.path.expanduser(path)).resolve()
    if not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(str(target), filename=target.name)


# ─── Process Manager ───

@app.get("/api/processes")
async def list_processes(sort: str = "cpu", user: dict = Depends(require_auth)):
    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status", "username"]):
        try:
            info = p.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"],
                "cpu": round(info["cpu_percent"] or 0, 1),
                "memory": round(info["memory_percent"] or 0, 1),
                "status": info["status"],
                "user": info["username"],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    key = "cpu" if sort == "cpu" else "memory"
    procs.sort(key=lambda x: x[key], reverse=True)
    return procs[:100]


@app.post("/api/processes/{pid}/kill")
async def kill_process(pid: int, user: dict = Depends(require_auth)):
    try:
        p = psutil.Process(pid)
        p.terminate()
        return {"status": "ok", "message": f"Process {pid} terminated"}
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail="Process not found")
    except psutil.AccessDenied:
        raise HTTPException(status_code=403, detail="Access denied")


# ─── GPU Info ───

@app.get("/api/gpu")
async def gpu_info(user: dict = Depends(require_auth)):
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return {"available": False}

        gpus = []
        for line in result.stdout.strip().split("\n"):
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 7:
                gpus.append({
                    "index": int(parts[0]),
                    "name": parts[1],
                    "temp_c": float(parts[2]),
                    "utilization": float(parts[3]),
                    "memory_used_mb": float(parts[4]),
                    "memory_total_mb": float(parts[5]),
                    "power_w": float(parts[6]) if parts[6] != "[N/A]" else None,
                })
        return {"available": True, "gpus": gpus}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"available": False}


# ─── Quick Actions (admin only) ───

@app.post("/api/action/shutdown")
async def shutdown_system(user: dict = Depends(require_admin)):
    os.system("shutdown -h +1")
    return {"status": "ok", "message": "System will shutdown in 1 minute"}


@app.post("/api/action/cancel-shutdown")
async def cancel_shutdown(user: dict = Depends(require_admin)):
    os.system("shutdown -c")
    return {"status": "ok", "message": "Shutdown cancelled"}


@app.post("/api/action/sleep")
async def sleep_system(user: dict = Depends(require_admin)):
    os.system("systemctl suspend")
    return {"status": "ok", "message": "System suspended"}


if __name__ == "__main__":
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    users = _load_users()
    port = 8765
    print("=" * 55)
    print("  PocketPC Server")
    print("=" * 55)
    print(f"  Local:   http://localhost:{port}")
    print(f"  Network: http://{local_ip}:{port}")
    print()
    if not users:
        print("  *** First run: open the above URL to create admin ***")
    else:
        print(f"  Registered users: {len(users)}")
    print()
    print("  On iPhone Safari, open the Network URL above,")
    print("  tap Share -> Add to Home Screen for app experience.")
    print("=" * 55)

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
