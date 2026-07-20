"""
🍌 Banana AI Trading — SaaS Admin Backend
Central hub that all desktop clients connect to.

Responsibilities:
- User authentication + license issuance (JWT-signed)
- WebSocket hub: receive telemetry from every desktop client
- Admin dashboard API: query live user state, push commands
- PostgreSQL: users, licenses, historical telemetry
- Redis: live state (5-min TTL), pub/sub between backend workers
"""
import os
import json
import time
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

import jwt
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import uvicorn

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
JWT_SECRET      = os.getenv("BANANA_JWT_SECRET", "change-me-in-production-256-bit-key")
JWT_ALGO        = "HS256"
LICENSE_TTL     = timedelta(days=30)
ADMIN_USER      = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD  = os.getenv("ADMIN_PASSWORD", "banana-admin-2026")
DATABASE_URL    = os.getenv("DATABASE_URL", "postgresql://banana:banana@localhost:5432/banana_saas")
REDIS_URL       = os.getenv("REDIS_URL", "redis://localhost:6379")

# ─────────────────────────────────────────────────────────────
# In-memory stores (replace with PostgreSQL + Redis in production)
# ─────────────────────────────────────────────────────────────
USERS: Dict[str, Dict[str, Any]] = {}          # user_id → user record
LICENSES: Dict[str, Dict[str, Any]] = {}       # token → license record
LIVE_STATE: Dict[str, Dict[str, Any]] = {}     # user_id → latest telemetry
TELEMETRY_HISTORY: List[Dict[str, Any]] = []   # rolling last 10k events
ADMIN_SESSIONS: Dict[str, str] = {}            # admin_token → username

# WebSocket connection registry
DEVICE_SOCKETS: Dict[str, WebSocket] = {}      # user_id → desktop socket
ADMIN_SOCKETS: List[WebSocket] = []            # list of admin dashboard subscribers

# ─────────────────────────────────────────────────────────────
# Seed demo users
# ─────────────────────────────────────────────────────────────
def _seed():
    demo_users = [
        {"user_id": "demo",       "password": "demo1234",    "plan": "free",       "email_or_telegram": "@demo"},
        {"user_id": "shri_ram",   "password": "banana2026",  "plan": "pro",        "email_or_telegram": "@shri_ram"},
        {"user_id": "alice_fx",   "password": "alice1234",   "plan": "pro",        "email_or_telegram": "123456"},
        {"user_id": "bob_gold",   "password": "bob1234",     "plan": "enterprise", "email_or_telegram": "234567"},
        {"user_id": "charlie_bt", "password": "charlie1234", "plan": "free",       "email_or_telegram": "345678"},
    ]
    for u in demo_users:
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.sha256(f"{u['password']}{salt}".encode()).hexdigest()
        USERS[u["user_id"]] = {
            "user_id": u["user_id"],
            "password_hash": pwd_hash,
            "salt": salt,
            "plan": u["plan"],
            "telegram": u["email_or_telegram"],
            "created_at": datetime.utcnow().isoformat(),
            "device_ids": [],
            "max_devices": {"free": 1, "pro": 3, "enterprise": 10}[u["plan"]],
            "status": "active",  # active | suspended | banned
        }
_seed()

# ─────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────
class LicenseValidateRequest(BaseModel):
    user_id: str
    password: str
    device_id: str
    app_version: Optional[str] = None
    platform: Optional[str] = None

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class AdminCommand(BaseModel):
    type: str                                 # stop_all_strategies | pause_strategy | send_notification | request_full_sync
    user_id: str
    strategy_id: Optional[str] = None
    title: Optional[str] = None
    body: Optional[str] = None

class UserStatusUpdate(BaseModel):
    status: str                               # active | suspended | banned

# ─────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🍌 Banana AI SaaS Admin Backend starting…")
    print(f"   Seeded users: {list(USERS.keys())}")
    print(f"   Admin login: {ADMIN_USER} / {ADMIN_PASSWORD}")
    yield

app = FastAPI(title="Banana AI SaaS Admin", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────
def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

def _issue_license(user: Dict[str, Any], device_id: str) -> Dict[str, Any]:
    expires_at = datetime.utcnow() + LICENSE_TTL
    payload = {
        "user_id": user["user_id"],
        "device_id": device_id,
        "plan": user["plan"],
        "iat": int(time.time()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    LICENSES[token] = {
        "user_id": user["user_id"],
        "device_id": device_id,
        "issued_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at.isoformat(),
        "plan": user["plan"],
    }
    return {"token": token, "expires_at": expires_at.isoformat(), "plan": user["plan"]}

def _verify_license_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_admin(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Admin auth required")
    tok = authorization[7:]
    admin = ADMIN_SESSIONS.get(tok)
    if not admin:
        raise HTTPException(401, "Invalid admin session")
    return admin

# ─────────────────────────────────────────────────────────────
# DESKTOP CLIENT ENDPOINTS (called by user's .exe)
# ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "Banana AI SaaS Admin", "version": "1.0.0", "status": "running"}

@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "users_registered": len(USERS),
        "active_licenses": len(LICENSES),
        "connected_devices": len(DEVICE_SOCKETS),
        "admin_dashboards": len(ADMIN_SOCKETS),
    }

@app.post("/api/license/validate")
async def validate_license(req: LicenseValidateRequest):
    """Called by desktop app on login. Verifies credentials + device binding + issues JWT."""
    user = USERS.get(req.user_id)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    if user.get("status") != "active":
        raise HTTPException(403, f"Account {user['status']}. Contact admin.")
    if _hash_password(req.password, user["salt"]) != user["password_hash"]:
        raise HTTPException(401, "Invalid credentials")

    # Device binding — enforce plan limit
    if req.device_id not in user["device_ids"]:
        if len(user["device_ids"]) >= user["max_devices"]:
            raise HTTPException(403, f"Device limit reached ({user['max_devices']}). Contact admin to reset.")
        user["device_ids"].append(req.device_id)

    license = _issue_license(user, req.device_id)
    return {
        "success": True,
        "user_id": user["user_id"],
        "plan": user["plan"],
        "token": license["token"],
        "expires_at": license["expires_at"],
    }

# ─────────────────────────────────────────────────────────────
# WEBSOCKET — Desktop → Cloud telemetry stream
# ─────────────────────────────────────────────────────────────
@app.websocket("/ws/device")
async def ws_device(ws: WebSocket, token: str = Query(...), device: str = Query(...)):
    """Every desktop app opens this WebSocket after login and streams telemetry every 5s."""
    payload = _verify_license_token(token)
    if not payload:
        await ws.close(code=4001, reason="Invalid or expired token")
        return
    if payload.get("device_id") != device:
        await ws.close(code=4002, reason="Device mismatch")
        return

    user_id = payload["user_id"]
    await ws.accept()
    DEVICE_SOCKETS[user_id] = ws
    print(f"🟢 Device connected: {user_id} ({device[:8]}…)")

    # Broadcast to admins that this user came online
    await _broadcast_to_admins({"type": "user_online", "user_id": user_id, "timestamp": time.time()})

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except:
                continue

            if msg.get("type") == "telemetry":
                # Store latest state
                LIVE_STATE[user_id] = {**msg, "received_at": time.time()}
                # Rolling history (last 10k)
                TELEMETRY_HISTORY.append({**msg, "received_at": time.time()})
                if len(TELEMETRY_HISTORY) > 10000:
                    TELEMETRY_HISTORY.pop(0)
                # Broadcast to any listening admins
                await _broadcast_to_admins({"type": "telemetry_update", "data": msg})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WS error for {user_id}: {e}")
    finally:
        DEVICE_SOCKETS.pop(user_id, None)
        if user_id in LIVE_STATE:
            LIVE_STATE[user_id]["mt5_connected"] = False
        print(f"🔴 Device disconnected: {user_id}")
        await _broadcast_to_admins({"type": "user_offline", "user_id": user_id, "timestamp": time.time()})

# ─────────────────────────────────────────────────────────────
# ADMIN ENDPOINTS (only you, the platform owner, use these)
# ─────────────────────────────────────────────────────────────
@app.post("/api/admin/login")
async def admin_login(req: AdminLoginRequest):
    if req.username != ADMIN_USER or req.password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin credentials")
    token = secrets.token_hex(32)
    ADMIN_SESSIONS[token] = req.username
    return {"success": True, "token": token, "username": req.username}

@app.get("/api/admin/overview")
async def admin_overview(admin: str = Depends(require_admin)):
    """High-level stats for admin dashboard."""
    online_users = len(DEVICE_SOCKETS)
    total_balance = sum(s.get("balance", 0) for s in LIVE_STATE.values())
    total_equity = sum(s.get("equity", 0) for s in LIVE_STATE.values())
    total_floating = sum(s.get("floating_pnl", 0) for s in LIVE_STATE.values())
    total_positions = sum(s.get("open_positions", 0) for s in LIVE_STATE.values())
    running_strats = sum(s.get("strategies_running", 0) for s in LIVE_STATE.values())

    by_plan: Dict[str, int] = {}
    for u in USERS.values():
        by_plan[u["plan"]] = by_plan.get(u["plan"], 0) + 1

    return {
        "users_total": len(USERS),
        "users_online": online_users,
        "users_offline": len(USERS) - online_users,
        "total_balance": round(total_balance, 2),
        "total_equity": round(total_equity, 2),
        "total_floating_pnl": round(total_floating, 2),
        "total_open_positions": total_positions,
        "total_running_strategies": running_strats,
        "users_by_plan": by_plan,
    }

@app.get("/api/admin/users")
async def admin_users(admin: str = Depends(require_admin)):
    """List of all users with live status."""
    out = []
    for uid, u in USERS.items():
        state = LIVE_STATE.get(uid, {})
        online = uid in DEVICE_SOCKETS
        out.append({
            "user_id": uid,
            "plan": u["plan"],
            "status": u.get("status", "active"),
            "telegram": u.get("telegram"),
            "created_at": u["created_at"],
            "devices_used": len(u["device_ids"]),
            "max_devices": u["max_devices"],
            "online": online,
            "last_seen": state.get("received_at"),
            "mt5_connected": state.get("mt5_connected", False),
            "balance": state.get("balance", 0),
            "equity": state.get("equity", 0),
            "floating_pnl": state.get("floating_pnl", 0),
            "open_positions": state.get("open_positions", 0),
            "strategies_running": state.get("strategies_running", 0),
            "strategies_total": state.get("strategies_total", 0),
            "cpu": state.get("cpu_percent", 0),
            "ram_mb": state.get("ram_mb", 0),
            "app_version": state.get("version"),
            "platform": state.get("platform"),
        })
    return {"users": out}

@app.get("/api/admin/users/{user_id}/detail")
async def admin_user_detail(user_id: str, admin: str = Depends(require_admin)):
    """Full detail for one user — strategies, positions, history."""
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    state = LIVE_STATE.get(user_id, {})
    history = [h for h in TELEMETRY_HISTORY[-500:] if h.get("user_id") == user_id]
    return {
        "profile": {
            "user_id": user_id,
            "plan": user["plan"],
            "status": user.get("status", "active"),
            "telegram": user.get("telegram"),
            "created_at": user["created_at"],
            "device_ids": user["device_ids"],
            "max_devices": user["max_devices"],
        },
        "live": state,
        "strategies": state.get("strategies_detail", []),
        "positions": state.get("positions_detail", []),
        "history": history,
    }

@app.post("/api/admin/users/{user_id}/command")
async def admin_send_command(user_id: str, cmd: AdminCommand, admin: str = Depends(require_admin)):
    """Push a command to a specific user's desktop client."""
    ws = DEVICE_SOCKETS.get(user_id)
    if not ws:
        raise HTTPException(404, f"User {user_id} is offline")
    try:
        await ws.send_text(json.dumps(cmd.model_dump()))
        return {"success": True, "delivered_at": time.time()}
    except Exception as e:
        raise HTTPException(500, f"Failed to send: {e}")

@app.post("/api/admin/users/{user_id}/broadcast")
async def admin_broadcast(user_id: str, cmd: AdminCommand, admin: str = Depends(require_admin)):
    """Alias — same as command endpoint."""
    return await admin_send_command(user_id, cmd, admin)

@app.patch("/api/admin/users/{user_id}/status")
async def admin_set_user_status(user_id: str, upd: UserStatusUpdate, admin: str = Depends(require_admin)):
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if upd.status not in ("active", "suspended", "banned"):
        raise HTTPException(400, "Invalid status")
    user["status"] = upd.status
    # Force disconnect if banned/suspended
    if upd.status != "active" and user_id in DEVICE_SOCKETS:
        try:
            await DEVICE_SOCKETS[user_id].close(code=4003, reason=f"Account {upd.status}")
        except:
            pass
    return {"success": True, "user_id": user_id, "status": upd.status}

@app.post("/api/admin/users/{user_id}/reset-devices")
async def admin_reset_devices(user_id: str, admin: str = Depends(require_admin)):
    """Clear all bound device_ids for a user (support ticket action)."""
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user["device_ids"] = []
    return {"success": True, "message": "Device bindings cleared"}

@app.post("/api/admin/users")
async def admin_create_user(body: Dict[str, Any], admin: str = Depends(require_admin)):
    """Create a new user."""
    uid = body.get("user_id")
    pwd = body.get("password")
    plan = body.get("plan", "free")
    if not uid or not pwd:
        raise HTTPException(400, "user_id and password required")
    if uid in USERS:
        raise HTTPException(409, "User already exists")
    salt = secrets.token_hex(16)
    USERS[uid] = {
        "user_id": uid,
        "password_hash": _hash_password(pwd, salt),
        "salt": salt,
        "plan": plan,
        "telegram": body.get("telegram"),
        "created_at": datetime.utcnow().isoformat(),
        "device_ids": [],
        "max_devices": {"free": 1, "pro": 3, "enterprise": 10}.get(plan, 1),
        "status": "active",
    }
    return {"success": True, "user_id": uid}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: str, admin: str = Depends(require_admin)):
    if user_id not in USERS:
        raise HTTPException(404, "User not found")
    del USERS[user_id]
    LIVE_STATE.pop(user_id, None)
    if user_id in DEVICE_SOCKETS:
        try: await DEVICE_SOCKETS[user_id].close(code=4004, reason="Account deleted")
        except: pass
    return {"success": True}

# ─────────────────────────────────────────────────────────────
# WEBSOCKET — Admin dashboard live feed
# ─────────────────────────────────────────────────────────────
@app.websocket("/ws/admin")
async def ws_admin(ws: WebSocket, token: str = Query(...)):
    if token not in ADMIN_SESSIONS:
        await ws.close(code=4001)
        return
    await ws.accept()
    ADMIN_SOCKETS.append(ws)
    print(f"📊 Admin dashboard connected ({len(ADMIN_SOCKETS)} total)")

    # Send initial snapshot
    try:
        await ws.send_text(json.dumps({
            "type": "snapshot",
            "live_state": LIVE_STATE,
            "online_users": list(DEVICE_SOCKETS.keys()),
        }))
        while True:
            _ = await ws.receive_text()   # keep alive; admins mainly listen
    except WebSocketDisconnect:
        pass
    finally:
        if ws in ADMIN_SOCKETS:
            ADMIN_SOCKETS.remove(ws)
        print(f"📊 Admin dashboard disconnected ({len(ADMIN_SOCKETS)} remaining)")

async def _broadcast_to_admins(message: Dict[str, Any]):
    """Push an event to every subscribed admin dashboard."""
    dead = []
    text = json.dumps(message)
    for ws in ADMIN_SOCKETS:
        try:
            await ws.send_text(text)
        except:
            dead.append(ws)
    for ws in dead:
        if ws in ADMIN_SOCKETS: ADMIN_SOCKETS.remove(ws)

# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
