import os
import uvicorn
import secrets
from fastapi import FastAPI, Request, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from models import Base, User, PasswordEntry
from auth import hash_password, verify_password
from crypto_utils import derive_master_key, derive_entry_key, encrypt_password, decrypt_password
from jinja2 import Environment, FileSystemLoader

DATABASE_URL = "sqlite:///./passwords.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32))

BASE_DIR = os.path.dirname(__file__)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

jinja_env = Environment(loader=FileSystemLoader(os.path.join(BASE_DIR, "templates")))

def render_template(template_name: str, request: Request, context: dict = None) -> HTMLResponse:
    if context is None:
        context = {}
    context.setdefault("request", request)
    template = jinja_env.get_template(template_name)
    html = template.render(**context)
    return HTMLResponse(content=html)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    return user

def require_unlocked(request: Request):
    if not request.session.get("master_key"):
        raise HTTPException(status_code=403, detail="Хранилище заблокировано. Перейдите на /unlock")

# ========== РОУТЫ ==========
@app.get("/", response_class=HTMLResponse, response_model=None)
async def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/vault")
    return RedirectResponse("/login")

@app.get("/register", response_class=HTMLResponse, response_model=None)
async def register_form(request: Request):
    return render_template("register.html", request)

@app.post("/register")
async def register(request: Request, username: str = Form(...), password: str = Form(...)):
    db = next(get_db())
    try:
        if db.query(User).filter(User.username == username).first():
            raise HTTPException(400, "Пользователь уже существует")
        salt = os.urandom(16)
        hashed = hash_password(password)
        user = User(username=username, password_hash=hashed, salt=salt)
        db.add(user)
        db.commit()
        return RedirectResponse("/login", status_code=302)
    finally:
        db.close()

@app.get("/login", response_class=HTMLResponse, response_model=None)
async def login_form(request: Request):
    return render_template("login.html", request)

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = next(get_db())
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(400, "Неверное имя пользователя или пароль")
        master_key = derive_master_key(password, user.salt)
        request.session["user_id"] = user.id
        request.session["master_key"] = master_key.hex()  # hex-строка
        return RedirectResponse("/vault", status_code=302)
    finally:
        db.close()

@app.get("/unlock", response_class=HTMLResponse, response_model=None)
async def unlock_form(request: Request):
    if not request.session.get("user_id"):
        return RedirectResponse("/login")
    return render_template("unlock.html", request)

@app.post("/unlock")
async def unlock(request: Request, password: str = Form(...)):
    db = next(get_db())
    try:
        user = get_current_user(request, db)
        if not verify_password(password, user.password_hash):
            raise HTTPException(403, "Неверный мастер-пароль")
        master_key = derive_master_key(password, user.salt)
        request.session["master_key"] = master_key.hex()
        return RedirectResponse("/vault", status_code=302)
    finally:
        db.close()

@app.get("/lock")
async def lock(request: Request):
    request.session.pop("master_key", None)
    return RedirectResponse("/unlock")

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")

@app.get("/vault", response_class=HTMLResponse, response_model=None)
async def vault(request: Request, page: int = Query(1, ge=1), per_page: int = Query(10, le=100), search: str = Query("")):
    db = next(get_db())
    try:
        user = get_current_user(request, db)
        require_unlocked(request)
        query = db.query(PasswordEntry).filter(PasswordEntry.user_id == user.id)
        if search:
            pattern = f"%{search}%"
            query = query.filter(
                (PasswordEntry.site.ilike(pattern)) |
                (PasswordEntry.login.ilike(pattern))
            )
        total = query.count()
        entries = query.order_by(PasswordEntry.site).offset((page - 1) * per_page).limit(per_page).all()
        return render_template("vault.html", request, {
            "entries": entries,
            "page": page,
            "per_page": per_page,
            "total": total,
            "search": search
        })
    finally:
        db.close()

@app.get("/entry/add", response_class=HTMLResponse, response_model=None)
async def add_entry_form(request: Request):
    db = next(get_db())
    try:
        get_current_user(request, db)
        require_unlocked(request)
        return render_template("add_entry.html", request)
    finally:
        db.close()

@app.post("/entry/add")
async def add_entry(request: Request,
                    site: str = Form(...),
                    url: str = Form(""),
                    login: str = Form(...),
                    password: str = Form(...)):
    db = next(get_db())
    try:
        user = get_current_user(request, db)
        require_unlocked(request)
        master_key = bytes.fromhex(request.session["master_key"])  # декодируем
        entry_key = derive_entry_key(master_key, site, login)
        enc_pwd = encrypt_password(password, entry_key)
        entry = PasswordEntry(user_id=user.id, site=site, url=url, login=login, encrypted_password=enc_pwd)
        db.add(entry)
        db.commit()
        return RedirectResponse("/vault", status_code=302)
    finally:
        db.close()

@app.get("/entry/{entry_id}/edit", response_class=HTMLResponse, response_model=None)
async def edit_entry_form(request: Request, entry_id: int):
    db = next(get_db())
    try:
        user = get_current_user(request, db)
        require_unlocked(request)
        entry = db.query(PasswordEntry).filter(
            PasswordEntry.id == entry_id, PasswordEntry.user_id == user.id).first()
        if not entry:
            raise HTTPException(404, "Запись не найдена")
        return render_template("edit_entry.html", request, {"entry": entry})
    finally:
        db.close()

@app.post("/entry/{entry_id}/edit")
async def edit_entry(request: Request, entry_id: int,
                     site: str = Form(...),
                     url: str = Form(""),
                     login: str = Form(...),
                     password: str = Form(...)):
    db = next(get_db())
    try:
        user = get_current_user(request, db)
        require_unlocked(request)
        entry = db.query(PasswordEntry).filter(
            PasswordEntry.id == entry_id, PasswordEntry.user_id == user.id).first()
        if not entry:
            raise HTTPException(404, "Запись не найдена")
        master_key = bytes.fromhex(request.session["master_key"])
        entry_key = derive_entry_key(master_key, site, login)
        enc_pwd = encrypt_password(password, entry_key)
        entry.site = site
        entry.url = url
        entry.login = login
        entry.encrypted_password = enc_pwd
        db.commit()
        return RedirectResponse("/vault", status_code=302)
    finally:
        db.close()

@app.post("/entry/{entry_id}/delete")
async def delete_entry(request: Request, entry_id: int):
    db = next(get_db())
    try:
        user = get_current_user(request, db)
        require_unlocked(request)
        entry = db.query(PasswordEntry).filter(
            PasswordEntry.id == entry_id, PasswordEntry.user_id == user.id).first()
        if not entry:
            raise HTTPException(404, "Запись не найдена")
        db.delete(entry)
        db.commit()
        return RedirectResponse("/vault", status_code=302)
    finally:
        db.close()

@app.get("/api/entry/{entry_id}/decrypt")
async def api_decrypt(request: Request, entry_id: int):
    db = next(get_db())
    try:
        user = get_current_user(request, db)
        require_unlocked(request)
        entry = db.query(PasswordEntry).filter(
            PasswordEntry.id == entry_id, PasswordEntry.user_id == user.id).first()
        if not entry:
            raise HTTPException(404, "Запись не найдена")
        master_key = bytes.fromhex(request.session["master_key"])
        entry_key = derive_entry_key(master_key, entry.site, entry.login)
        plain = decrypt_password(entry.encrypted_password, entry_key)
        return {"password": plain}
    finally:
        db.close()

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)