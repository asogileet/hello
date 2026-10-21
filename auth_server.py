#!/usr/bin/env python3
import hashlib
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_state.json")
SALT = "streetview_salt_2026:"
# Default initial SHA-256 for 888888 (can be changed anytime via /hello/api/change_pin)
DEFAULT_PIN_HASH = "67025bc08639f8879dccc4235bf62db69b0166634a1bedb32da053f7ff911ed7"
MAX_ATTEMPTS = 3


def hash_pin(pin: str) -> str:
    return hashlib.sha256((SALT + pin).encode("utf-8")).hexdigest()


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "pin_hash" in data and "ip_records" in data and "tokens" in data:
                    return data
        except Exception:
            pass
    return {
        "pin_hash": DEFAULT_PIN_HASH,
        "ip_records": {},  # ip -> {"fails": int, "banned": bool, "banned_at": float}
        "tokens": {}       # token -> {"created_at": float}
    }


def save_state(state: dict) -> None:
    tmp_file = STATE_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp_file, STATE_FILE)


class AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def get_client_ip(self) -> str:
        # Prefer Cloudflare real IP, then X-Forwarded-For, then X-Real-IP, then socket IP
        cf_ip = self.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip.strip()
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        xri = self.headers.get("X-Real-IP")
        if xri:
            return xri.strip()
        return self.client_address[0]

    def send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        state = load_state()
        ip = self.get_client_ip()
        rec = state["ip_records"].get(ip, {"fails": 0, "banned": False})

        if self.path.startswith("/hello/api/status"):
            self.send_json(200, {
                "ip": ip,
                "fails": rec.get("fails", 0),
                "remaining": max(0, MAX_ATTEMPTS - rec.get("fails", 0)),
                "banned": bool(rec.get("banned", False))
            })
            return

        self.send_json(404, {"error": "Not Found"})

    def do_POST(self):
        state = load_state()
        ip = self.get_client_ip()
        rec = state["ip_records"].get(ip, {"fails": 0, "banned": False, "banned_at": 0})
        body = self.read_json()

        # 1. Verify PIN endpoint
        if self.path.startswith("/hello/api/verify_pin"):
            if rec.get("banned"):
                self.send_json(403, {
                    "ok": False,
                    "banned": True,
                    "ip": ip,
                    "message": f"⛔ 您的 IP ({ip}) 因密碼錯誤滿 3 次已被永久封鎖！"
                })
                return

            pin = str(body.get("pin", "")).strip()
            if not pin:
                self.send_json(400, {"ok": False, "message": "請輸入存取密碼。"})
                return

            if hash_pin(pin) == state["pin_hash"]:
                # Success: reset fails for this IP and issue an admin token
                state["ip_records"][ip] = {"fails": 0, "banned": False, "banned_at": 0}
                token = secrets.token_hex(24)
                state["tokens"][token] = {"ip": ip, "created_at": time.time()}
                save_state(state)
                self.send_json(200, {
                    "ok": True,
                    "ip": ip,
                    "token": token,
                    "message": "🎉 驗證成功，歡迎光臨！"
                })
            else:
                fails = rec.get("fails", 0) + 1
                banned = fails >= MAX_ATTEMPTS
                state["ip_records"][ip] = {
                    "fails": fails,
                    "banned": banned,
                    "banned_at": time.time() if banned else 0
                }
                save_state(state)

                if banned:
                    self.send_json(403, {
                        "ok": False,
                        "banned": True,
                        "ip": ip,
                        "fails": fails,
                        "remaining": 0,
                        "message": f"⛔ 密碼連續錯誤滿 3 次！您的 IP ({ip}) 已被系統封鎖！"
                    })
                else:
                    rem = MAX_ATTEMPTS - fails
                    self.send_json(401, {
                        "ok": False,
                        "banned": False,
                        "ip": ip,
                        "fails": fails,
                        "remaining": rem,
                        "message": f"❌ 存取密碼錯誤（剩餘 {rem} 次機會，滿 3 次將封鎖 IP：{ip}）"
                    })
            return

        # 2. Issue admin token after Google Sign-In (so Google user can also change PIN / unban IPs)
        if self.path.startswith("/hello/api/google_session"):
            email = str(body.get("email", "")).strip().lower()
            if email == "edwin.shinsoft@gmail.com":
                # Also unban current IP if owner logged in with Google!
                state["ip_records"][ip] = {"fails": 0, "banned": False, "banned_at": 0}
                token = secrets.token_hex(24)
                state["tokens"][token] = {"ip": ip, "created_at": time.time()}
                save_state(state)
                self.send_json(200, {"ok": True, "token": token, "ip": ip})
            else:
                self.send_json(403, {"ok": False, "message": "未授權的 Google 帳號"})
            return

        # 3. Change PIN on server (requires valid session token)
        if self.path.startswith("/hello/api/change_pin"):
            token = str(body.get("token", "")).strip()
            new_pin = str(body.get("new_pin", "")).strip()
            if not token or token not in state["tokens"]:
                self.send_json(401, {"ok": False, "message": "請先重新登入後再修改密碼！"})
                return
            if len(new_pin) < 4:
                self.send_json(400, {"ok": False, "message": "新密碼長度至少需 4 碼！"})
                return

            state["pin_hash"] = hash_pin(new_pin)
            save_state(state)
            self.send_json(200, {"ok": True, "message": "✅ 伺服器存取密碼已加密更新完成（所有裝置立即生效）！"})
            return

        # 4. Unban all IPs (owner utility in settings)
        if self.path.startswith("/hello/api/unban_all"):
            token = str(body.get("token", "")).strip()
            if not token or token not in state["tokens"]:
                self.send_json(401, {"ok": False, "message": "未授權"})
                return
            state["ip_records"] = {}
            save_state(state)
            self.send_json(200, {"ok": True, "message": "✅ 已清空所有封鎖 IP 紀錄！"})
            return

        self.send_json(404, {"error": "Not Found"})


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8788), AuthHandler)
    print("Hello Auth Server listening on 127.0.0.1:8788", flush=True)
    server.serve_forever()
