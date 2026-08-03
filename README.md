from __future__ import annotations

import secrets
import string
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Flask, jsonify, render_template, request

DEMO_KEYS = [
    {"key": "STL-7XK2-9FQD-8LPM", "status": "Активен", "hwid": "—", "expires": "01 сен 2026", "expires_at": "2026-09-01T00:00:00+00:00", "created": "02 авг 2026"},
    {"key": "STL-A4D9-2MNV-K8QP", "status": "Использован", "hwid": "7c:1a:••:94", "expires": "Навсегда", "expires_at": None, "created": "29 июл 2026"},
    {"key": "STL-E1B7-W5RT-C3ZX", "status": "Истёк", "hwid": "—", "expires": "01 авг 2026", "expires_at": "2026-08-01T00:00:00+00:00", "created": "02 июл 2026"},
]

REDIS_KEY = "stealthbypass:keys:v1"


def load_local_env() -> None:
    """Load local secrets without adding another runtime dependency."""
    env_file = Path(__file__).with_name(".env")
    if not env_file.exists():
        return
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip('"').strip("'"))


class StorageError(RuntimeError):
    pass


class RedisKeyStore:
    def __init__(self, url: str, token: str):
        if not url or not token:
            raise StorageError("Не заданы UPSTASH_REDIS_REST_URL или UPSTASH_REDIS_REST_TOKEN")
        self.url = url.rstrip("/")
        self.token = token

    @classmethod
    def from_environment(cls) -> "RedisKeyStore":
        load_local_env()
        return cls(
            os.environ.get("UPSTASH_REDIS_REST_URL", ""),
            os.environ.get("UPSTASH_REDIS_REST_TOKEN", ""),
        )

    def command(self, *command: str):
        data = json.dumps(list(command)).encode("utf-8")
        request = Request(
            self.url,
            data=data,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError) as error:
            raise StorageError("Redis временно недоступен") from error
        if "error" in payload:
            raise StorageError("Redis вернул ошибку")
        return payload.get("result")

    def load(self) -> list[dict]:
        raw = self.command("GET", REDIS_KEY)
        if raw is None:
            initial = [item.copy() for item in DEMO_KEYS]
            self.save(initial)
            return initial
        return json.loads(raw)

    def save(self, items: list[dict]) -> None:
        self.command("SET", REDIS_KEY, json.dumps(items, ensure_ascii=False))


app = Flask(__name__)
_store: RedisKeyStore | None = None


def store() -> RedisKeyStore:
    global _store
    if _store is None:
        _store = RedisKeyStore.from_environment()
    return _store


def generate_key(prefix: str) -> str:
    alphabet = string.ascii_uppercase + string.digits
    safe_prefix = "".join(char for char in prefix.upper() if char.isalnum())[:10] or "STL"
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "-".join([safe_prefix, *groups])


def expiry(duration: str) -> tuple[str, str | None]:
    if duration == "forever":
        return "Навсегда", None
    days = {"7": 7, "30": 30, "90": 90}.get(duration, 30)
    expires_at = datetime.now(timezone.utc) + timedelta(days=days)
    return expires_at.strftime("%d.%m.%Y"), expires_at.isoformat()


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/keys")
def list_keys():
    try:
        return jsonify(store().load())
    except StorageError as error:
        return jsonify({"error": str(error)}), 503


@app.post("/api/keys")
def create_key():
    try:
        payload = request.get_json(silent=True) or {}
        expires, expires_at = expiry(str(payload.get("duration", "30")))
        item = {
            "key": generate_key(str(payload.get("prefix", "STL"))),
            "status": "Активен",
            "hwid": "—",
            "expires": expires,
            "expires_at": expires_at,
            "created": datetime.now().strftime("%d.%m.%Y"),
        }
        items = store().load()
        items.insert(0, item)
        store().save(items)
        return jsonify(item), 201
    except StorageError as error:
        return jsonify({"error": str(error)}), 503


@app.delete("/api/keys/<path:key_value>")
def delete_key(key_value: str):
    try:
        items = store().load()
        index = next((i for i, item in enumerate(items) if item["key"] == key_value), None)
        if index is None:
            return jsonify({"error": "Ключ не найден"}), 404
        items.pop(index)
        store().save(items)
        return "", 204
    except StorageError as error:
        return jsonify({"error": str(error)}), 503


@app.post("/api/auth")
def authenticate():
    """ActivationManager-compatible key/HWID verification endpoint."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "reason": "Некорректное тело запроса"})

    key_value = str(payload.get("key", "")).strip().upper()
    hwid = str(payload.get("hwid", "")).strip()
    if not key_value or not hwid:
        return jsonify({"ok": False, "reason": "Не указан ключ или HWID"})

    try:
        items = store().load()
    except StorageError:
        return jsonify({"ok": False, "reason": "Сервис ключей временно недоступен"})

    item = next((item for item in items if item["key"] == key_value), None)
    if item is None:
        return jsonify({"ok": False, "reason": "Ключ не найден"})
    if item["status"] == "Истёк":
        return jsonify({"ok": False, "reason": "Срок действия ключа истёк"})

    expires_at = item.get("expires_at")
    if expires_at and datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc):
        item["status"] = "Истёк"
        store().save(items)
        return jsonify({"ok": False, "reason": "Срок действия ключа истёк"})

    if item["hwid"] not in ("—", hwid):
        return jsonify({"ok": False, "reason": "Ключ уже привязан к другому HWID"})

    item["hwid"] = hwid
    item["status"] = "Использован"
    try:
        store().save(items)
    except StorageError:
        return jsonify({"ok": False, "reason": "Сервис ключей временно недоступен"})
    return jsonify({"ok": True, "reason": "Активация подтверждена"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
