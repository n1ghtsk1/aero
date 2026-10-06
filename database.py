"""
База данных SQLite: подключение, схема и миграции.

Используется встроенный модуль sqlite3 — без ORM и внешних зависимостей.
Файл database.db создаётся автоматически при первом запуске.
"""

import random
import sqlite3
from contextlib import closing
from datetime import date, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"


def get_connection() -> sqlite3.Connection:
    """Новое соединение на каждый запрос: для SQLite это дёшево и потокобезопасно."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row             # строки можно читать как словари
    conn.execute("PRAGMA foreign_keys = ON")   # SQLite проверяет внешние ключи только с этим флагом
    return conn


# ---------------------------------------------------------------------------
# Схема
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE,              -- всегда в нижнем регистре
    hashed_password TEXT    NOT NULL,                     -- pbkdf2_sha256$итерации$соль$хеш
    is_admin        INTEGER NOT NULL DEFAULT 0,           -- 0 / 1
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Сессии входа: в cookie лежит случайный токен, здесь — только его SHA-256
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT    NOT NULL,                          -- ISO-время в UTC
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Аэропорты / направления. code — код IATA (MOW, IST…), по нему ищутся рейсы
CREATE TABLE IF NOT EXISTS airports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    country    TEXT NOT NULL,
    city       TEXT NOT NULL,
    code       TEXT NOT NULL UNIQUE,                      -- 3 латинские буквы, верхний регистр
    name       TEXT NOT NULL,                             -- название аэропорта
    country_en TEXT,                                      -- необязательные названия для английской версии
    city_en    TEXT
);

-- Расписание. Аэропорт нельзя удалить, пока на него есть рейсы (RESTRICT)
CREATE TABLE IF NOT EXISTS flights (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    flight_number    TEXT    NOT NULL,                    -- «SU 1234»: первые 2 символа — код авиакомпании
    origin_code      TEXT    NOT NULL REFERENCES airports(code) ON DELETE RESTRICT,
    destination_code TEXT    NOT NULL REFERENCES airports(code) ON DELETE RESTRICT,
    departure_time   TEXT    NOT NULL,                    -- местное время вылета: 2026-10-12T08:45
    duration_minutes INTEGER NOT NULL DEFAULT 120,
    price            REAL    NOT NULL,                    -- за пассажира, ₽
    seats_available  INTEGER NOT NULL,
    baggage          INTEGER NOT NULL DEFAULT 1           -- включён ли багаж в тариф
);

CREATE TABLE IF NOT EXISTS bookings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    flight_id      INTEGER REFERENCES flights(id) ON DELETE SET NULL,
    pax            INTEGER NOT NULL DEFAULT 1,            -- сколько мест занимает заказ
    passenger_name TEXT    NOT NULL,
    route          TEXT    NOT NULL,
    flight_date    TEXT    NOT NULL,                      -- ISO-дата: 2026-10-12
    price          REAL    NOT NULL,                      -- в рублях
    status         TEXT    NOT NULL DEFAULT 'В обработке',
    payment_method TEXT    NOT NULL DEFAULT 'card',
    pnr            TEXT,                                  -- код бронирования
    details        TEXT,                                  -- JSON: рейс, места, пассажиры
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS support_requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    name        TEXT NOT NULL,
    contact     TEXT NOT NULL,                            -- e-mail / телефон / @telegram
    topic       TEXT NOT NULL DEFAULT 'other',            -- refund / baggage / payment / other
    message     TEXT NOT NULL,
    booking_pnr TEXT,
    status      TEXT NOT NULL DEFAULT 'Новое',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

# Колонки, появившиеся после первых версий. Если database.db создана раньше,
# init_db() добавит их через ALTER TABLE — старые данные не потеряются.
MIGRATIONS = {
    "bookings": {
        "payment_method": "payment_method TEXT NOT NULL DEFAULT 'card'",
        "pnr": "pnr TEXT",
        "user_id": "user_id INTEGER REFERENCES users(id) ON DELETE SET NULL",
        "details": "details TEXT",
        "flight_id": "flight_id INTEGER REFERENCES flights(id) ON DELETE SET NULL",
        "pax": "pax INTEGER NOT NULL DEFAULT 1",
    },
    "support_requests": {
        "user_id": "user_id INTEGER REFERENCES users(id) ON DELETE SET NULL",
    },
}

# Индексы создаются после миграций: им нужны новые колонки
INDEXES = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_bookings_pnr  ON bookings(pnr);   -- NULL у старых заказов не мешает
CREATE        INDEX IF NOT EXISTS idx_bookings_user ON bookings(user_id);
CREATE        INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE        INDEX IF NOT EXISTS idx_flights_route ON flights(origin_code, destination_code, departure_time);
"""


# ---------------------------------------------------------------------------
# Стартовые данные: чтобы поиск работал сразу после первого запуска.
# Заполняются один раз (PRAGMA user_version), дальше всё меняет администратор.
# ---------------------------------------------------------------------------
SEED_VERSION = 1

# (страна, город, код, аэропорт, страна EN, город EN)
SEED_AIRPORTS = [
    ("Россия", "Москва", "MOW", "Шереметьево", "Russia", "Moscow"),
    ("Россия", "Санкт-Петербург", "LED", "Пулково", "Russia", "Saint Petersburg"),
    ("Россия", "Казань", "KZN", "Казань", "Russia", "Kazan"),
    ("Россия", "Сочи", "AER", "Сочи (Адлер)", "Russia", "Sochi"),
    ("Турция", "Стамбул", "IST", "Стамбул", "Türkiye", "Istanbul"),
    ("Турция", "Анталья", "AYT", "Анталья", "Türkiye", "Antalya"),
    ("ОАЭ", "Дубай", "DXB", "Дубай Интернешнл", "UAE", "Dubai"),
    ("Грузия", "Тбилиси", "TBS", "Тбилиси им. Шота Руставели", "Georgia", "Tbilisi"),
    ("Армения", "Ереван", "EVN", "Звартноц", "Armenia", "Yerevan"),
    ("Казахстан", "Алматы", "ALA", "Алматы", "Kazakhstan", "Almaty"),
    ("Таиланд", "Бангкок", "BKK", "Суварнабхуми", "Thailand", "Bangkok"),
    ("Франция", "Париж", "PAR", "Шарль-де-Голль", "France", "Paris"),
    ("Испания", "Барселона", "BCN", "Эль-Прат", "Spain", "Barcelona"),
]

# (откуда, куда, авиакомпании, минут в пути, базовая цена ₽) — в расписание попадают оба направления
SEED_ROUTES = [
    ("MOW", "IST", ["SU", "TK", "DP"], 230, 9500),
    ("MOW", "DXB", ["EK", "SU"], 325, 18500),
    ("MOW", "TBS", ["SU", "U6"], 170, 8900),
    ("MOW", "AYT", ["SU", "DP", "U6"], 250, 11200),
    ("MOW", "EVN", ["SU", "U6"], 185, 8400),
    ("MOW", "ALA", ["SU", "S7"], 270, 12900),
    ("MOW", "BKK", ["SU", "QR"], 560, 34500),
    ("MOW", "AER", ["SU", "DP", "S7"], 150, 5200),
    ("MOW", "KZN", ["SU", "DP"], 95, 3900),
    ("MOW", "LED", ["SU", "DP", "S7"], 85, 3600),
    ("LED", "IST", ["TK", "SU"], 245, 10200),
    ("IST", "PAR", ["TK"], 230, 14500),
    ("IST", "BCN", ["TK"], 235, 13800),
]
SEED_DAYS = 28


def seed_data(conn: sqlite3.Connection) -> None:
    """Аэропорты и расписание на SEED_DAYS дней вперёд (детерминированно)."""
    conn.executemany(
        "INSERT OR IGNORE INTO airports (country, city, code, name, country_en, city_en) VALUES (?, ?, ?, ?, ?, ?)",
        SEED_AIRPORTS,
    )
    if conn.execute("SELECT 1 FROM flights LIMIT 1").fetchone():
        return
    rows = []
    start = date.today() + timedelta(days=1)
    for origin, dest, airlines, minutes, base in SEED_ROUTES:
        for a, b in ((origin, dest), (dest, origin)):
            rnd = random.Random(f"{a}-{b}")
            numbers = {al: f"{al} {rnd.randint(100, 2999)}" for al in airlines}   # у авиакомпании постоянный номер рейса
            for day in range(SEED_DAYS):
                for _ in range(rnd.choice((1, 1, 2, 2, 3))):
                    airline = rnd.choice(airlines)
                    hour, minute = rnd.randint(6, 22), rnd.choice(range(0, 60, 5))
                    rows.append((
                        numbers[airline], a, b,
                        f"{start + timedelta(days=day)}T{hour:02d}:{minute:02d}",
                        minutes + rnd.choice((-10, -5, 0, 5, 10)),
                        round(base * rnd.uniform(0.85, 1.35), -1),
                        rnd.choice((3, 7, 12, 24, 48, 96, 150, 180)),
                        int(rnd.random() < 0.65),
                    ))
    conn.executemany(
        """INSERT INTO flights (flight_number, origin_code, destination_code, departure_time,
                                duration_minutes, price, seats_available, baggage)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )


def init_db() -> None:
    """Создаёт таблицы, применяет миграции и индексы. Безопасно вызывать при каждом старте."""
    # closing() закрывает соединение, а `with conn` фиксирует транзакцию
    with closing(get_connection()) as conn, conn:
        conn.executescript(SCHEMA)
        for table, columns in MIGRATIONS.items():
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            for column, ddl in columns.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        conn.executescript(INDEXES)
        if conn.execute("PRAGMA user_version").fetchone()[0] < SEED_VERSION:
            seed_data(conn)
            conn.execute(f"PRAGMA user_version = {SEED_VERSION}")
