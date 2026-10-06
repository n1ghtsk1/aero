"""
Безопасность: хеширование паролей, сессии и проверка прав доступа.

Пароли — PBKDF2-HMAC-SHA256 из стандартной библиотеки (как в Django),
сессии — случайный токен в HttpOnly-cookie, в базе хранится только его хеш.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from fastapi import Cookie, Depends, HTTPException, Response, status

from database import get_connection

# ---------------------------------------------------------------------------
# Пароли
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS = 600_000   # рекомендация OWASP для PBKDF2-SHA256


def hash_password(password: str) -> str:
    """Хеш с уникальной солью в формате pbkdf2_sha256$итерации$соль$хеш."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Сравнение за постоянное время — по скорости ответа нельзя угадать хеш."""
    try:
        algorithm, iterations, salt_hex, hash_hex = stored.split("$")
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
    return hmac.compare_digest(digest.hex(), hash_hex)


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return hash_password(secrets.token_urlsafe(16))


def burn_password_check() -> None:
    """
    Вход с несуществующим e-mail тратит столько же времени, сколько с существующим.
    Иначе по скорости ответа можно было бы узнать, кто зарегистрирован.
    """
    verify_password("x", _dummy_hash())


# ---------------------------------------------------------------------------
# Сессии
# ---------------------------------------------------------------------------
SESSION_COOKIE = "aero_session"
SESSION_TTL = timedelta(days=30)
# На HTTPS включите: AERO_SECURE_COOKIES=1 — cookie не будет уходить по незащищённому каналу
SECURE_COOKIES = os.getenv("AERO_SECURE_COOKIES") == "1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _token_hash(token: str) -> str:
    # Если базу украдут, по хешам нельзя войти от имени пользователей
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    """Создаёт сессию и возвращает токен для cookie. Заодно чистит просроченные."""
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_now(),))
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + SESSION_TTL).isoformat()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        (_token_hash(token), user_id, expires_at),
    )
    return token


def delete_session(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,        # JavaScript не видит токен — XSS не сможет его украсть
        samesite="lax",       # чужие сайты не смогут отправить POST с этой cookie
        secure=SECURE_COOKIES,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="lax", secure=SECURE_COOKIES)


# ---------------------------------------------------------------------------
# Зависимости FastAPI: кто делает запрос и что ему можно
# ---------------------------------------------------------------------------
def current_user(token: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> sqlite3.Row | None:
    """Пользователь по cookie сессии или None, если не вошёл (сессия истекла)."""
    if not token:
        return None
    with closing(get_connection()) as conn:
        return conn.execute(
            """
            SELECT u.* FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ?
            """,
            (_token_hash(token), _now()),
        ).fetchone()


def require_user(user: sqlite3.Row | None = Depends(current_user)) -> sqlite3.Row:
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Войдите в аккаунт")
    return user


def require_admin(user: sqlite3.Row = Depends(require_user)) -> sqlite3.Row:
    if not user["is_admin"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Доступно только администраторам")
    return user
