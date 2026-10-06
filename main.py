"""
Aero — бэкенд сайта авиабилетов.

FastAPI + SQLite (встроенный модуль sqlite3, без внешних ORM).

Структура проекта:
    main.py            — этот файл: схемы данных и маршруты API
    database.py        — подключение к SQLite, схема и миграции
    security.py        — пароли, сессии, проверка прав
    requirements.txt   — зависимости
    static/index.html  — фронтенд (и админ-панель по адресу /admin)
    database.db        — создаётся автоматически при первом запуске

Запуск сервера:
    uvicorn main:app --reload

Назначить администратора (создаст пользователя или повысит существующего):
    python main.py create-admin admin@example.com
"""

import argparse
import json
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager, closing
from datetime import date, datetime
from getpass import getpass
from typing import Any, Literal

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from database import BASE_DIR, get_connection, init_db
from security import (
    SESSION_COOKIE,
    burn_password_check,
    clear_session_cookie,
    create_session,
    current_user,
    delete_session,
    hash_password,
    require_admin,
    require_user,
    set_session_cookie,
    verify_password,
)

STATIC_DIR = BASE_DIR / "static"     # наружу раздаётся только эта папка

# ---------------------------------------------------------------------------
# Допустимые значения
# ---------------------------------------------------------------------------
BookingStatus = Literal["В обработке", "Оплачено", "Подтверждён", "Отменён"]
# Пользователь может отменить только активное бронирование на ещё не прошедший рейс
CANCELLABLE_STATUSES = ("В обработке", "Оплачено", "Подтверждён")
PAID_STATUSES = ("Оплачено", "Подтверждён")   # учитываются в выручке
PaymentMethod = Literal["card", "sbp", "usdt"]   # банковская карта / СБП / USDT TRC20
SupportTopic = Literal["refund", "baggage", "payment", "other"]

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
# Контакт для ответа поддержки: e-mail, телефон или @username в Telegram
CONTACT_PATTERNS = (
    EMAIL_RE,
    re.compile(r"^\+?[\d\s()-]{10,18}$"),
    re.compile(r"^@[A-Za-z0-9_]{5,32}$"),
)
SUPPORT_REPLY_MINUTES = 10
MAX_DETAILS_BYTES = 16_000           # снимок рейса из фронтенда — не больше 16 КБ

FLIGHT_NO_RE = re.compile(r"^([A-Z0-9]{2})(\d{1,4})$")   # SU1234 → «SU 1234»
SEAT_RE = re.compile(r"^\d{1,2}[A-F]$")
UNSAFE_TEXT_RE = re.compile(r"[<>\"'&`]")
# Места повышенной комфортности (ряды 1–3 эконома) — те же правила, что на схеме салона во фронтенде
COMFORT_ROWS = 3
SEAT_COMFORT_FEE = 1500

# Код бронирования (PNR): 6 символов без похожих I/O/0/1
PNR_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_pnr(conn: sqlite3.Connection) -> str:
    """Случайный код бронирования, которого ещё нет в базе."""
    while True:
        pnr = "".join(secrets.choice(PNR_ALPHABET) for _ in range(6))
        if not conn.execute("SELECT 1 FROM bookings WHERE pnr = ?", (pnr,)).fetchone():
            return pnr


# ---------------------------------------------------------------------------
# Схемы: пользователи
# ---------------------------------------------------------------------------
class LoginIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: str = Field(max_length=254, examples=["anna@example.com"])
    # При входе не раскрываем правила пароля — достаточно, чтобы он был не пустым
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.lower()
        if not EMAIL_RE.match(value):
            raise ValueError("Некорректный e-mail")
        return value


class RegisterIn(LoginIn):
    password: str = Field(min_length=8, max_length=128, examples=["SkyHigh2026"])

    @field_validator("password")
    @classmethod
    def check_strength(cls, value: str) -> str:
        if not (re.search(r"[A-Za-zА-Яа-яЁё]", value) and re.search(r"\d", value)):
            raise ValueError("Пароль должен содержать буквы и цифры")
        return value


class UserOut(BaseModel):
    id: int
    email: str
    is_admin: bool
    created_at: datetime


class AuthOut(BaseModel):
    success: bool = True
    user: UserOut


class MeOut(BaseModel):
    user: UserOut | None   # None — посетитель не вошёл


def user_out(row: sqlite3.Row) -> UserOut:
    return UserOut(id=row["id"], email=row["email"], is_admin=bool(row["is_admin"]), created_at=row["created_at"])


# ---------------------------------------------------------------------------
# Схемы: заказы
# ---------------------------------------------------------------------------
class BookingCreate(BaseModel):
    """
    То, что присылает фронтенд в POST /api/book после успешной оплаты.

    Цену, маршрут и дату сервер берёт из рейса — браузеру не доверяем.
    Реквизиты карты сюда НЕ приходят и не хранятся: в реальном проекте
    их принимает платёжный провайдер, а нам возвращает только результат.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    flight_id: int
    passenger_name: str = Field(min_length=2, max_length=100, examples=["Ivan Petrov"])
    pax: int = Field(default=1, ge=1, le=9)
    seats: list[str] = Field(default_factory=list, max_length=9, examples=[["4A", "4B"]])
    cabin: Literal["economy", "business"] = "economy"
    payment_method: PaymentMethod = "card"
    # Снимок рейса для посадочного талона: авиакомпания, время, места
    details: dict[str, Any] | None = None

    @field_validator("seats")
    @classmethod
    def check_seats(cls, value: list[str]) -> list[str]:
        value = [s.upper() for s in value]
        if any(not SEAT_RE.match(s) for s in value) or len(set(value)) != len(value):
            raise ValueError("Некорректный список мест")
        return value

    @field_validator("details")
    @classmethod
    def limit_details(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None and len(json.dumps(value, ensure_ascii=False)) > MAX_DETAILS_BYTES:
            raise ValueError("Слишком большой объём данных о рейсе")
        return value

    @model_validator(mode="after")
    def seats_not_more_than_pax(self) -> "BookingCreate":
        if len(self.seats) > self.pax:
            raise ValueError("Мест выбрано больше, чем пассажиров")
        return self


class Booking(BaseModel):
    """Заказ в том виде, в каком он хранится в базе."""

    id: int
    user_id: int | None = None     # None — у заказов, созданных до появления аккаунтов
    flight_id: int | None = None   # None — старые заказы или рейс удалён из расписания
    pax: int = 1
    passenger_name: str
    route: str
    flight_date: date
    price: float
    status: BookingStatus
    payment_method: PaymentMethod = "card"
    pnr: str | None = None
    details: dict[str, Any] | None = None
    created_at: datetime


class AdminBooking(Booking):
    """Заказ в админ-панели — с e-mail владельца."""

    user_email: str | None = None


class BookingCreated(BaseModel):
    success: bool = True
    id: int
    booking: Booking


class BookingUpdate(BaseModel):
    """PATCH из админ-панели: передаются только изменяемые поля."""

    model_config = ConfigDict(str_strip_whitespace=True)

    passenger_name: str | None = Field(default=None, min_length=2, max_length=100)
    route: str | None = Field(default=None, min_length=3, max_length=120)
    flight_date: date | None = None
    price: float | None = Field(default=None, gt=0)
    status: BookingStatus | None = None


class AdminStats(BaseModel):
    bookings: int
    users: int
    revenue: float     # сумма оплаченных и подтверждённых заказов, ₽
    pending: int       # заказов «В обработке»
    canceled: int      # отменённых заказов


def booking_from_row(row: sqlite3.Row, model: type[Booking] = Booking) -> Booking:
    data = dict(row)
    data["details"] = json.loads(data["details"]) if data.get("details") else None
    return model(**data)


# ---------------------------------------------------------------------------
# Схемы: аэропорты и рейсы
# ---------------------------------------------------------------------------
class AirportIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    country: str = Field(min_length=2, max_length=60, examples=["Япония"])
    city: str = Field(min_length=1, max_length=60, examples=["Токио"])
    code: str = Field(pattern=r"^[A-Za-z]{3}$", examples=["TYO"])
    name: str = Field(min_length=2, max_length=80, examples=["Нарита"])
    country_en: str | None = Field(default=None, max_length=60, examples=["Japan"])
    city_en: str | None = Field(default=None, max_length=60, examples=["Tokyo"])

    @field_validator("code")
    @classmethod
    def upper_code(cls, value: str) -> str:
        return value.upper()

    @field_validator("country", "city", "name", "country_en", "city_en")
    @classmethod
    def plain_text(cls, value: str | None) -> str | None:
        # Названия выводятся на сайте — HTML-символы в них не нужны (защита от XSS)
        if value and UNSAFE_TEXT_RE.search(value):
            raise ValueError("Недопустимые символы: < > \" ' & `")
        return value or None


class Airport(AirportIn):
    id: int


class AdminAirport(Airport):
    flights_count: int = 0   # сколько рейсов связано — такой аэропорт удалить нельзя


class FlightIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    flight_number: str = Field(examples=["SU 2134"])
    origin_code: str = Field(pattern=r"^[A-Za-z]{3}$", examples=["MOW"])
    destination_code: str = Field(pattern=r"^[A-Za-z]{3}$", examples=["IST"])
    departure_time: datetime = Field(examples=["2026-10-20T08:45"])   # местное время вылета
    duration_minutes: int = Field(default=120, ge=20, le=1440)
    price: float = Field(gt=0, le=10_000_000, examples=[9800])
    seats_available: int = Field(ge=0, le=1000, examples=[150])
    baggage: bool = True

    @field_validator("flight_number")
    @classmethod
    def normalize_number(cls, value: str) -> str:
        match = FLIGHT_NO_RE.match(value.replace(" ", "").upper())
        if not match:
            raise ValueError("Номер рейса: 2 символа авиакомпании и до 4 цифр, например SU 1234")
        return f"{match[1]} {match[2]}"

    @field_validator("origin_code", "destination_code")
    @classmethod
    def upper_code(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def different_airports(self) -> "FlightIn":
        if self.origin_code == self.destination_code:
            raise ValueError("Аэропорты отправления и прибытия должны различаться")
        return self


class Flight(BaseModel):
    id: int
    flight_number: str
    origin_code: str
    destination_code: str
    departure_time: str          # «2026-10-20T08:45» — без часового пояса, как в табло
    duration_minutes: int
    price: float
    seats_available: int
    baggage: bool


class FlightSearch(BaseModel):
    flights: list[Flight]
    # Если на выбранную дату пусто — ближайшие даты с рейсами и минимальной ценой
    nearby: list[dict[str, Any]]


def flight_from_row(row: sqlite3.Row) -> Flight:
    return Flight(**{key: row[key] for key in Flight.model_fields})


def now_local() -> str:
    """Текущее время в формате колонки departure_time — для сравнения строк."""
    return datetime.now().strftime("%Y-%m-%dT%H:%M")


def take_seats(conn: sqlite3.Connection, flight_id: int | None, pax: int) -> None:
    """Списать места с рейса атомарно: UPDATE сработает, только если мест хватает."""
    if flight_id is None or not conn.execute("SELECT 1 FROM flights WHERE id = ?", (flight_id,)).fetchone():
        return   # рейс удалён из расписания — считать нечего
    cursor = conn.execute(
        "UPDATE flights SET seats_available = seats_available - ? WHERE id = ? AND seats_available >= ?",
        (pax, flight_id, pax),
    )
    if cursor.rowcount == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "На рейсе не осталось столько свободных мест")


def release_seats(conn: sqlite3.Connection, flight_id: int | None, pax: int) -> None:
    """Вернуть места на рейс (отмена или удаление активного заказа)."""
    if flight_id is not None:
        conn.execute("UPDATE flights SET seats_available = seats_available + ? WHERE id = ?", (pax, flight_id))


# ---------------------------------------------------------------------------
# Схемы: поддержка
# ---------------------------------------------------------------------------
class SupportIn(BaseModel):
    """Сообщение из формы «Служба заботы»."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=2, max_length=100, examples=["Anna Smirnova"])
    contact: str = Field(min_length=3, max_length=100, examples=["anna@example.com", "@anna_travels"])
    topic: SupportTopic = "other"
    message: str = Field(min_length=10, max_length=1000, examples=["Хочу вернуть билет, рейс перенесли."])
    booking_pnr: str | None = Field(default=None, max_length=12, examples=["SNUQCV"])

    @field_validator("contact")
    @classmethod
    def check_contact(cls, value: str) -> str:
        if not any(p.match(value) for p in CONTACT_PATTERNS):
            raise ValueError("Укажите e-mail, телефон или @username в Telegram")
        return value

    @field_validator("booking_pnr")
    @classmethod
    def empty_pnr_to_none(cls, value: str | None) -> str | None:
        return value or None


class SupportCreated(BaseModel):
    success: bool = True
    id: int
    ticket_number: str                                   # например, SUP-000042
    reply_within_minutes: int = SUPPORT_REPLY_MINUTES


# ---------------------------------------------------------------------------
# Приложение
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()  # выполняется один раз при старте сервера
    yield


app = FastAPI(title="Aero API", version="2.0.0", lifespan=lifespan)


# ----------------------------- Авторизация ---------------------------------
@app.post("/api/register", response_model=AuthOut, status_code=status.HTTP_201_CREATED, summary="Регистрация")
def register(data: RegisterIn, response: Response) -> AuthOut:
    """Создаёт пользователя и сразу выполняет вход (ставит cookie сессии)."""
    with closing(get_connection()) as conn, conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (data.email,)).fetchone():
            raise HTTPException(status.HTTP_409_CONFLICT, "Этот e-mail уже зарегистрирован")
        cursor = conn.execute(
            "INSERT INTO users (email, hashed_password) VALUES (?, ?)",
            (data.email, hash_password(data.password)),
        )
        token = create_session(conn, cursor.lastrowid)
        row = conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
    set_session_cookie(response, token)
    return AuthOut(user=user_out(row))


@app.post("/api/login", response_model=AuthOut, summary="Вход")
def login(data: LoginIn, response: Response) -> AuthOut:
    with closing(get_connection()) as conn, conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (data.email,)).fetchone()
        if row is None:
            burn_password_check()
        if row is None or not verify_password(data.password, row["hashed_password"]):
            # Одинаковый ответ для «нет такого e-mail» и «неверный пароль»
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Неверный e-mail или пароль")
        token = create_session(conn, row["id"])
    set_session_cookie(response, token)
    return AuthOut(user=user_out(row))


@app.post("/api/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Выход")
def logout(token: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> Response:
    """Удаляет сессию из базы — украденная cookie после выхода тоже перестанет работать."""
    if token:
        with closing(get_connection()) as conn, conn:
            delete_session(conn, token)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(response)
    return response


@app.get("/api/me", response_model=MeOut, summary="Текущий пользователь")
def me(user: sqlite3.Row | None = Depends(current_user)) -> MeOut:
    return MeOut(user=user_out(user) if user else None)


# ------------------------------- Заказы ------------------------------------
@app.post("/api/book", response_model=BookingCreated, status_code=status.HTTP_201_CREATED, summary="Создать бронирование")
def create_booking(data: BookingCreate, user: sqlite3.Row = Depends(require_user)) -> BookingCreated:
    """
    Оформляет билет на рейс из расписания: списывает места, считает цену по рейсу
    (+ доплата за места «Комфорт»), присваивает PNR. Всё — в одной транзакции.
    """
    with closing(get_connection()) as conn, conn:
        flight = conn.execute(
            """
            SELECT f.*, o.city AS origin_city, d.city AS destination_city
            FROM flights f
            LEFT JOIN airports o ON o.code = f.origin_code
            LEFT JOIN airports d ON d.code = f.destination_code
            WHERE f.id = ?
            """,
            (data.flight_id,),
        ).fetchone()
        if flight is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Рейс не найден — возможно, его убрали из расписания")
        if flight["departure_time"] <= now_local():
            raise HTTPException(status.HTTP_409_CONFLICT, "Этот рейс уже вылетел")
        take_seats(conn, flight["id"], data.pax)

        comfort_seats = sum(int(s[:-1]) <= COMFORT_ROWS for s in data.seats) if data.cabin == "economy" else 0
        price = flight["price"] * data.pax + comfort_seats * SEAT_COMFORT_FEE
        route = (f"{flight['origin_city'] or flight['origin_code']} ({flight['origin_code']}) → "
                 f"{flight['destination_city'] or flight['destination_code']} ({flight['destination_code']})")
        # Параметры передаются через «?» — это защищает от SQL-инъекций
        cursor = conn.execute(
            """
            INSERT INTO bookings (user_id, flight_id, pax, passenger_name, route, flight_date, price,
                                  status, payment_method, pnr, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Оплачено', ?, ?, ?)
            """,
            (
                user["id"],
                flight["id"],
                data.pax,
                data.passenger_name,
                route,
                flight["departure_time"][:10],
                price,
                data.payment_method,
                generate_pnr(conn),
                json.dumps(data.details, ensure_ascii=False) if data.details else None,
            ),
        )
        row = conn.execute("SELECT * FROM bookings WHERE id = ?", (cursor.lastrowid,)).fetchone()

    booking = booking_from_row(row)
    return BookingCreated(id=booking.id, booking=booking)


@app.get("/api/bookings", response_model=list[Booking], summary="Мои заказы")
def list_my_bookings(user: sqlite3.Row = Depends(require_user)) -> list[Booking]:
    """Только заказы текущего пользователя, новые — первыми."""
    with closing(get_connection()) as conn:
        rows = conn.execute("SELECT * FROM bookings WHERE user_id = ? ORDER BY id DESC", (user["id"],)).fetchall()
    return [booking_from_row(row) for row in rows]


@app.post("/api/bookings/{booking_id}/cancel", response_model=Booking, summary="Отменить своё бронирование")
def cancel_my_booking(booking_id: int, user: sqlite3.Row = Depends(require_user)) -> Booking:
    """
    Пользователь отменяет СВОЙ заказ. Чужой заказ — 404 (не раскрываем, что он существует).
    Нельзя отменить уже отменённый заказ или рейс, дата которого прошла — 409.
    """
    with closing(get_connection()) as conn, conn:
        row = conn.execute(
            "SELECT * FROM bookings WHERE id = ? AND user_id = ?", (booking_id, user["id"])
        ).fetchone()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Заказ не найден")
        if row["status"] not in CANCELLABLE_STATUSES:
            raise HTTPException(status.HTTP_409_CONFLICT, "Это бронирование уже нельзя отменить")
        if date.fromisoformat(row["flight_date"]) < date.today():
            raise HTTPException(status.HTTP_409_CONFLICT, "Рейс уже состоялся — отмена недоступна")
        conn.execute("UPDATE bookings SET status = 'Отменён' WHERE id = ?", (booking_id,))
        release_seats(conn, row["flight_id"], row["pax"])   # места снова доступны другим
        row = conn.execute("SELECT * FROM bookings WHERE id = ?", (booking_id,)).fetchone()
    return booking_from_row(row)


# ----------------------------- Админ-панель --------------------------------
@app.get("/api/admin/bookings", response_model=list[AdminBooking], summary="Все заказы (админ)")
def admin_list_bookings(_: sqlite3.Row = Depends(require_admin)) -> list[AdminBooking]:
    with closing(get_connection()) as conn:
        rows = conn.execute(
            """
            SELECT b.*, u.email AS user_email
            FROM bookings b LEFT JOIN users u ON u.id = b.user_id
            ORDER BY b.id DESC
            """
        ).fetchall()
    return [booking_from_row(row, AdminBooking) for row in rows]


@app.get("/api/admin/stats", response_model=AdminStats, summary="Сводка (админ)")
def admin_stats(_: sqlite3.Row = Depends(require_admin)) -> AdminStats:
    with closing(get_connection()) as conn:
        row = conn.execute(
            f"""
            SELECT
              (SELECT COUNT(*) FROM bookings)                                                   AS bookings,
              (SELECT COUNT(*) FROM users)                                                      AS users,
              (SELECT COALESCE(SUM(price), 0) FROM bookings WHERE status IN ({",".join("?" * len(PAID_STATUSES))})) AS revenue,
              (SELECT COUNT(*) FROM bookings WHERE status = 'В обработке')                      AS pending,
              (SELECT COUNT(*) FROM bookings WHERE status = 'Отменён')                          AS canceled
            """,
            PAID_STATUSES,
        ).fetchone()
    return AdminStats(**dict(row))


@app.patch("/api/admin/bookings/{booking_id}", response_model=AdminBooking, summary="Изменить заказ (админ)")
def admin_update_booking(booking_id: int, data: BookingUpdate, _: sqlite3.Row = Depends(require_admin)) -> AdminBooking:
    changes = data.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Нет полей для изменения")
    if "flight_date" in changes:
        changes["flight_date"] = changes["flight_date"].isoformat()
    # Имена колонок берутся только из схемы BookingUpdate, а значения — через «?»
    assignments = ", ".join(f"{column} = ?" for column in changes)
    with closing(get_connection()) as conn, conn:
        old = conn.execute("SELECT * FROM bookings WHERE id = ?", (booking_id,)).fetchone()
        if old is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Заказ не найден")
        # Отмена возвращает места на рейс, «воскрешение» отменённого заказа — снова их занимает
        if "status" in changes:
            was_active, now_active = old["status"] != "Отменён", changes["status"] != "Отменён"
            if was_active and not now_active:
                release_seats(conn, old["flight_id"], old["pax"])
            elif now_active and not was_active:
                take_seats(conn, old["flight_id"], old["pax"])
        conn.execute(f"UPDATE bookings SET {assignments} WHERE id = ?", (*changes.values(), booking_id))
        row = conn.execute(
            "SELECT b.*, u.email AS user_email FROM bookings b LEFT JOIN users u ON u.id = b.user_id WHERE b.id = ?",
            (booking_id,),
        ).fetchone()
    return booking_from_row(row, AdminBooking)


@app.delete("/api/admin/bookings/{booking_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Удалить заказ (админ)")
def admin_delete_booking(booking_id: int, _: sqlite3.Row = Depends(require_admin)) -> Response:
    with closing(get_connection()) as conn, conn:
        row = conn.execute("SELECT * FROM bookings WHERE id = ?", (booking_id,)).fetchone()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Заказ не найден")
        if row["status"] != "Отменён":
            release_seats(conn, row["flight_id"], row["pax"])
        conn.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------- Направления и расписание -------------------------
@app.get("/api/airports", response_model=list[Airport], summary="Аэропорты (для полей «Откуда/Куда»)")
def list_airports() -> list[Airport]:
    with closing(get_connection()) as conn:
        rows = conn.execute("SELECT * FROM airports ORDER BY country, city").fetchall()
    return [Airport(**dict(row)) for row in rows]


@app.get("/api/flights", response_model=FlightSearch, summary="Поиск рейсов")
def search_flights(
    origin: str = Query(alias="from", pattern=r"^[A-Za-z]{3}$"),
    destination: str = Query(alias="to", pattern=r"^[A-Za-z]{3}$"),
    day: date = Query(alias="date"),
    pax: int = Query(default=1, ge=1, le=9),
) -> FlightSearch:
    """Рейсы на дату с достаточным числом мест; если их нет — ближайшие даты с ценой «от»."""
    origin, destination = origin.upper(), destination.upper()
    route_filter = "origin_code = ? AND destination_code = ? AND seats_available >= ? AND departure_time > ?"
    params = (origin, destination, pax, now_local())
    with closing(get_connection()) as conn:
        rows = conn.execute(
            f"SELECT * FROM flights WHERE {route_filter} AND substr(departure_time, 1, 10) = ? ORDER BY departure_time",
            (*params, day.isoformat()),
        ).fetchall()
        nearby = [] if rows else conn.execute(
            f"""
            SELECT substr(departure_time, 1, 10) AS date, MIN(price) AS min_price
            FROM flights WHERE {route_filter}
            GROUP BY date ORDER BY ABS(julianday(date) - julianday(?)) LIMIT 4
            """,
            (*params, day.isoformat()),
        ).fetchall()
    return FlightSearch(
        flights=[flight_from_row(row) for row in rows],
        nearby=sorted((dict(row) for row in nearby), key=lambda r: r["date"]),
    )


@app.get("/api/admin/airports", response_model=list[AdminAirport], summary="Аэропорты с числом рейсов (админ)")
def admin_list_airports(_: sqlite3.Row = Depends(require_admin)) -> list[AdminAirport]:
    with closing(get_connection()) as conn:
        rows = conn.execute(
            """
            SELECT a.*, (SELECT COUNT(*) FROM flights f
                         WHERE f.origin_code = a.code OR f.destination_code = a.code) AS flights_count
            FROM airports a ORDER BY a.country, a.city
            """
        ).fetchall()
    return [AdminAirport(**dict(row)) for row in rows]


@app.post("/api/admin/airports", response_model=AdminAirport, status_code=status.HTTP_201_CREATED, summary="Добавить аэропорт (админ)")
def admin_create_airport(data: AirportIn, _: sqlite3.Row = Depends(require_admin)) -> AdminAirport:
    with closing(get_connection()) as conn, conn:
        if conn.execute("SELECT 1 FROM airports WHERE code = ?", (data.code,)).fetchone():
            raise HTTPException(status.HTTP_409_CONFLICT, f"Аэропорт с кодом {data.code} уже есть")
        cursor = conn.execute(
            "INSERT INTO airports (country, city, code, name, country_en, city_en) VALUES (?, ?, ?, ?, ?, ?)",
            (data.country, data.city, data.code, data.name, data.country_en, data.city_en),
        )
    return AdminAirport(id=cursor.lastrowid, **data.model_dump())


@app.delete("/api/admin/airports/{airport_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Удалить аэропорт (админ)")
def admin_delete_airport(airport_id: int, _: sqlite3.Row = Depends(require_admin)) -> Response:
    with closing(get_connection()) as conn, conn:
        row = conn.execute("SELECT code FROM airports WHERE id = ?", (airport_id,)).fetchone()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Аэропорт не найден")
        used = conn.execute(
            "SELECT COUNT(*) FROM flights WHERE origin_code = ? OR destination_code = ?", (row["code"], row["code"])
        ).fetchone()[0]
        if used:
            raise HTTPException(status.HTTP_409_CONFLICT, f"Сначала удалите рейсы этого аэропорта: {used}")
        conn.execute("DELETE FROM airports WHERE id = ?", (airport_id,))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/admin/flights", response_model=list[Flight], summary="Всё расписание (админ)")
def admin_list_flights(_: sqlite3.Row = Depends(require_admin)) -> list[Flight]:
    with closing(get_connection()) as conn:
        rows = conn.execute("SELECT * FROM flights ORDER BY departure_time").fetchall()
    return [flight_from_row(row) for row in rows]


@app.post("/api/admin/flights", response_model=Flight, status_code=status.HTTP_201_CREATED, summary="Добавить рейс (админ)")
def admin_create_flight(data: FlightIn, _: sqlite3.Row = Depends(require_admin)) -> Flight:
    with closing(get_connection()) as conn, conn:
        known = {row["code"] for row in conn.execute(
            "SELECT code FROM airports WHERE code IN (?, ?)", (data.origin_code, data.destination_code)
        )}
        missing = {data.origin_code, data.destination_code} - known
        if missing:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Нет такого аэропорта: {', '.join(sorted(missing))}")
        cursor = conn.execute(
            """INSERT INTO flights (flight_number, origin_code, destination_code, departure_time,
                                    duration_minutes, price, seats_available, baggage)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (data.flight_number, data.origin_code, data.destination_code,
             data.departure_time.strftime("%Y-%m-%dT%H:%M"), data.duration_minutes,
             data.price, data.seats_available, int(data.baggage)),
        )
        row = conn.execute("SELECT * FROM flights WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return flight_from_row(row)


@app.delete("/api/admin/flights/{flight_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Удалить рейс (админ)")
def admin_delete_flight(flight_id: int, _: sqlite3.Row = Depends(require_admin)) -> Response:
    """Купленные билеты остаются: у них сохранён снимок рейса, а flight_id станет NULL."""
    with closing(get_connection()) as conn, conn:
        if conn.execute("DELETE FROM flights WHERE id = ?", (flight_id,)).rowcount == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Рейс не найден")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------ Поддержка ----------------------------------
@app.post("/api/support", response_model=SupportCreated, status_code=status.HTTP_201_CREATED, summary="Сообщение в поддержку")
def create_support_request(data: SupportIn, user: sqlite3.Row | None = Depends(current_user)) -> SupportCreated:
    """Сохраняет обращение (гостю тоже можно писать) и возвращает его номер."""
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute(
            """
            INSERT INTO support_requests (user_id, name, contact, topic, message, booking_pnr)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user["id"] if user else None, data.name, data.contact, data.topic, data.message, data.booking_pnr),
        )
    request_id = cursor.lastrowid
    # Здесь удобно уведомлять операторов: письмо, сообщение в Telegram-чат и т.п.
    return SupportCreated(id=request_id, ticket_number=f"SUP-{request_id:06d}")


# ------------------------------- Фронтенд ----------------------------------
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    """Главная страница — сайт с авиабилетами."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/admin", include_in_schema=False, response_model=None)
def admin_page(user: sqlite3.Row | None = Depends(current_user)) -> FileResponse | RedirectResponse:
    """
    Скрытый раздел. Гостя отправляем на вход, обычному пользователю отвечаем 404 —
    так даже не видно, что админка существует. Данные дополнительно защищены в /api/admin/*.
    """
    if user is None:
        return RedirectResponse("/?next=admin", status_code=status.HTTP_303_SEE_OTHER)
    if not user["is_admin"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return FileResponse(STATIC_DIR / "index.html")


# Остальные статические файлы (CSS, JS, картинки), если появятся: /static/...
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Командная строка: python main.py create-admin admin@example.com
# ---------------------------------------------------------------------------
def create_admin(email: str) -> None:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise SystemExit("Некорректный e-mail")
    init_db()
    with closing(get_connection()) as conn, conn:
        row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if row:
            conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (row["id"],))
            print(f"✓ {email} теперь администратор")
            return

    # Пароль спрашиваем вне транзакции, чтобы не блокировать базу на время ввода
    password = getpass("Пароль (минимум 8 символов, буквы и цифры): ")
    try:
        RegisterIn(email=email, password=password)
    except ValueError as error:
        raise SystemExit(f"Пароль не подходит: {error.errors()[0]['msg']}")
    if getpass("Повторите пароль: ") != password:
        raise SystemExit("Пароли не совпадают")
    with closing(get_connection()) as conn, conn:
        conn.execute(
            "INSERT INTO users (email, hashed_password, is_admin) VALUES (?, ?, 1)",
            (email, hash_password(password)),
        )
        print(f"✓ Создан администратор {email}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aero — служебные команды")
    commands = parser.add_subparsers(dest="command", required=True)
    admin_cmd = commands.add_parser("create-admin", help="создать администратора или повысить пользователя")
    admin_cmd.add_argument("email")
    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin(args.email)
