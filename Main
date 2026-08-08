"""
Secure Chat - FastAPI backend
- Email + password signup/login (JWT auth)
- Messages encrypted at rest with AES-256-GCM
- SQLite storage via SQLAlchemy
- WebSocket signaling for voice/video calls (WebRTC)
"""
import os
import json
import base64
import datetime
from typing import List, Dict

from fastapi import (
    FastAPI, Depends, HTTPException, status,
    WebSocket, WebSocketDisconnect, Query,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import jwt, JWTError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("JWT_SECRET", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

# 32-byte key for AES-256-GCM. In production, set MESSAGE_ENC_KEY as a
# base64-encoded 32-byte value in your host's secrets. If missing, a key is
# generated at startup (messages will not survive a restart in that case).
_raw_key = os.environ.get("MESSAGE_ENC_KEY")
if _raw_key:
    ENC_KEY = base64.b64decode(_raw_key)
else:
    ENC_KEY = AESGCM.generate_key(bit_length=256)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = "sqlite:///./secure_chat.db"

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    sent_messages = relationship(
        "Message", foreign_keys="Message.sender_id", back_populates="sender"
    )


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_email = Column(String, index=True, nullable=False)
    nonce = Column(String, nullable=False)       # base64
    ciphertext = Column(String, nullable=False)  # base64
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")


def hash_password(password: str) -> str:
    truncated = password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.hash(truncated)


def verify_password(plain: str, hashed: str) -> bool:
    truncated = plain.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.verify(truncated, hashed)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


def encrypt_message(plaintext: str) -> tuple[str, str]:
    aesgcm = AESGCM(ENC_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()


def decrypt_message(nonce_b64: str, ct_b64: str) -> str:
    aesgcm = AESGCM(ENC_KEY)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    email = decode_token(token)
    if email is None:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class SignupRequest(BaseModel):
    email: EmailStr
    username: str
    phone: str | None = None
    password: str


class MessageOut(BaseModel):
    id: int
    sender_email: str
    sender_username: str
    receiver_email: str
    text: str
    is_read: bool
    created_at: datetime.datetime


class ConversationOut(BaseModel):
    email: str
    username: str
    last_message: str
    last_time: datetime.datetime
    last_sender_email: str
    last_message_read: bool
    unread_count: int


class UserSearchOut(BaseModel):
    email: str
    username: str


class SendMessageRequest(BaseModel):
    receiver_email: EmailStr
    text: str


# ---------------------------------------------------------------------------
# WebSocket connection manager (for call signaling)
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active: Dict[str, WebSocket] = {}

    async def connect(self, email: str, websocket: WebSocket):
        await websocket.accept()
        self.active[email] = websocket

    def disconnect(self, email: str):
        self.active.pop(email, None)

    async def send_to(self, email: str, message: dict) -> bool:
        ws = self.active.get(email)
        if ws is None:
            return False
        try:
            await ws.send_text(json.dumps(message))
            return True
        except Exception:
            return False


manager = ConnectionManager()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Secure Chat")


@app.post("/api/signup", status_code=201)
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    username = payload.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    existing_username = db.query(User).filter(User.username == username).first()
    if existing_username:
        raise HTTPException(status_code=400, detail="Username already taken")
    phone = payload.phone.strip() if payload.phone else None
    if phone:
        existing_phone = db.query(User).filter(User.phone == phone).first()
        if existing_phone:
            raise HTTPException(status_code=400, detail="Phone number already registered")
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    user = User(
        email=payload.email,
        username=username,
        phone=phone,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token({"sub": user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "email": user.email,
        "username": user.username,
        "phone": user.phone,
    }


@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    identifier = form_data.username.strip()
    user = (
        db.query(User)
        .filter((User.email == identifier) | (User.phone == identifier))
        .first()
    )
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token({"sub": user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "email": user.email,
        "username": user.username,
        "phone": user.phone,
    }


@app.get("/api/me")
def read_me(current_user: User = Depends(get_current_user)):
    return {
        "email": current_user.email,
        "username": current_user.username,
        "phone": current_user.phone,
    }


@app.post("/api/messages", status_code=201)
def send_message(
    payload: SendMessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    recipient = db.query(User).filter(User.email == payload.receiver_email).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    nonce_b64, ct_b64 = encrypt_message(payload.text)
    msg = Message(
        sender_id=current_user.id,
        receiver_email=payload.receiver_email,
        nonce=nonce_b64,
        ciphertext=ct_b64,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return {"id": msg.id, "created_at": msg.created_at}


@app.get("/api/messages/{other_email}", response_model=List[MessageOut])
def get_conversation(
    other_email: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    other = db.query(User).filter(User.email == other_email).first()
    if not other:
        raise HTTPException(status_code=404, detail="User not found")
    rows = (
        db.query(Message)
        .filter(
            (
                (Message.sender_id == current_user.id)
                & (Message.receiver_email == other.email)
            )
            | (
                (Message.sender_id == other.id)
                & (Message.receiver_email == current_user.email)
            )
        )
        .order_by(Message.created_at.asc())
        .all()
    )
    result = []
    for row in rows:
        try:
            text = decrypt_message(row.nonce, row.ciphertext)
        except Exception:
            text = "[unable to decrypt]"
        result.append(
            MessageOut(
                id=row.id,
                sender_email=row.sender.email,
                sender_username=row.sender.username,
                receiver_email=row.receiver_email,
                text=text,
                is_read=row.is_read,
                created_at=row.created_at,
            )
        )

    # Mark messages the other user sent to us as read, now that we've viewed them
    unread_from_other = [
        r for r in rows if r.sender_id == other.id and r.receiver_email == current_user.email and not r.is_read
    ]
    if unread_from_other:
        for r in unread_from_other:
            r.is_read = True
        db.commit()

    return result


@app.get("/api/conversations", response_model=List[ConversationOut])
def get_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Message)
        .filter(
            (Message.sender_id == current_user.id)
            | (Message.receiver_email == current_user.email)
        )
        .order_by(Message.created_at.desc())
        .all()
    )

    latest_by_partner: Dict[str, Message] = {}
    for row in rows:
        partner_email = row.receiver_email if row.sender_id == current_user.id else row.sender.email
        if partner_email == current_user.email:
            continue
        if partner_email not in latest_by_partner:
            latest_by_partner[partner_email] = row

    conversations = []
    for partner_email, last_msg in latest_by_partner.items():
        partner = db.query(User).filter(User.email == partner_email).first()
        if not partner:
            continue
        unread_count = (
            db.query(Message)
            .filter(
                Message.sender_id == partner.id,
                Message.receiver_email == current_user.email,
                Message.is_read == False,  # noqa: E712
            )
            .count()
        )
        try:
            text = decrypt_message(last_msg.nonce, last_msg.ciphertext)
        except Exception:
            text = "[unable to decrypt]"
        conversations.append(
            ConversationOut(
                email=partner.email,
                username=partner.username,
                last_message=text,
                last_time=last_msg.created_at,
                last_sender_email=last_msg.sender.email,
                last_message_read=last_msg.is_read,
                unread_count=unread_count,
            )
        )

    conversations.sort(key=lambda c: c.last_time, reverse=True)
    return conversations


@app.get("/api/users/search", response_model=List[UserSearchOut])
def search_users(
    q: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = q.strip()
    if not q:
        return []
    like_q = f"%{q}%"
    users = (
        db.query(User)
        .filter(
            (User.username.ilike(like_q)) | (User.email.ilike(like_q))
        )
        .filter(User.email != current_user.email)
        .limit(20)
        .all()
    )
    return [UserSearchOut(email=u.email, username=u.username) for u in users]


# ---------------------------------------------------------------------------
# WebSocket: call signaling (WebRTC offer/answer/ICE relay)
# ---------------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...), db: Session = Depends(get_db)):
    email = decode_token(token)
    if email is None:
        await websocket.close(code=4401)
        return
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        await websocket.close(code=4401)
        return

    await manager.connect(email, websocket)
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type")
            to_email = data.get("to")
            if not msg_type or not to_email:
                continue

            outgoing = {"type": msg_type, "from": email, "from_username": user.username}
            if msg_type == "call-offer":
                outgoing["sdp"] = data.get("sdp")
                outgoing["video"] = data.get("video", False)
            elif msg_type == "call-answer":
                outgoing["sdp"] = data.get("sdp")
            elif msg_type == "ice-candidate":
                outgoing["candidate"] = data.get("candidate")
            # call-reject, call-end, call-busy need no extra payload

            delivered = await manager.send_to(to_email, outgoing)
            if not delivered and msg_type == "call-offer":
                # Recipient offline: tell caller immediately
                await manager.send_to(email, {"type": "call-reject", "from": to_email, "from_username": to_email})
    except WebSocketDisconnect:
        manager.disconnect(email)
    except Exception:
        manager.disconnect(email)


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


@app.get("/icon-192.png")
def icon_192():
    return FileResponse(os.path.join(BASE_DIR, "icon-192-new.png"))


@app.get("/icon-512.png")
def icon_512():
    return FileResponse(os.path.join(BASE_DIR, "icon-512-new.png"))


@app.get("/")
def index():
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
