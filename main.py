"""
Secure Chat - FastAPI backend
- Email + password signup/login (JWT auth)
- Messages encrypted at rest with AES-256-GCM
- SQLite storage via SQLAlchemy
- WebSocket signaling for voice/video calls (WebRTC)
"""
import os
import json
import uuid
import base64
import random
import hashlib
import smtplib
import datetime
import mimetypes
from email.mime.text import MIMEText
from typing import List, Dict, Optional

from fastapi import (
    FastAPI, Depends, HTTPException, status,
    WebSocket, WebSocketDisconnect, Query,
    UploadFile, File,
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

# --- Database URL ---
# Uses a persistent Postgres database (e.g. Neon, Supabase) when DATABASE_URL
# is set in the environment. Falls back to a local SQLite file for local
# development only. On Render's free tier, local SQLite is NOT persistent
# across restarts/redeploys — always set DATABASE_URL in production.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./secure_chat.db")

# Some hosts provide URLs starting with "postgres://", but SQLAlchemy needs
# "postgresql://" — normalize it here so both forms work.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# --- File uploads (chat attachments + profile pictures) ---
# NOTE: on Render's free tier, disk storage is NOT persistent across
# restarts/redeploys. Uploaded files may disappear when the service restarts.
# For permanent storage, use a paid plan with a persistent disk, or an
# external storage service (S3, Cloudinary, etc).
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
MAX_UPLOAD_BYTES = 15 * 1024 * 1024  # 15 MB

# --- SMTP config for sending OTP emails (all via environment variables) ---
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)
OTP_EXPIRE_MINUTES = 10

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
# check_same_thread is only needed/valid for SQLite connections.
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    avatar_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    sent_messages = relationship(
        "Message", foreign_keys="Message.sender_id", back_populates="sender"
    )


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_email = Column(String, index=True, nullable=False)
    nonce = Column(String, nullable=True)         # base64, null for file-only messages
    ciphertext = Column(String, nullable=True)    # base64, null for file-only messages
    file_url = Column(String, nullable=True)
    file_name = Column(String, nullable=True)
    file_type = Column(String, nullable=True)
    is_read = Column(Boolean, default=False, nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)
    is_edited = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")


class Group(Base):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    avatar_url = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class GroupMember(Base):
    __tablename__ = "group_members"
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    joined_at = Column(DateTime, default=datetime.datetime.utcnow)


class GroupMessage(Base):
    __tablename__ = "group_messages"
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    nonce = Column(String, nullable=True)
    ciphertext = Column(String, nullable=True)
    file_url = Column(String, nullable=True)
    file_name = Column(String, nullable=True)
    file_type = Column(String, nullable=True)
    is_deleted = Column(Boolean, default=False, nullable=False)
    is_edited = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    sender = relationship("User", foreign_keys=[sender_id])


class PasswordResetOTP(Base):
    __tablename__ = "password_reset_otps"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    code_hash = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class CallLog(Base):
    __tablename__ = "call_logs"
    id = Column(Integer, primary_key=True, index=True)
    caller_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    callee_email = Column(String, index=True, nullable=False)
    is_video = Column(Boolean, default=False, nullable=False)
    # status: "completed" | "missed" | "busy" | "canceled"
    status = Column(String, nullable=False)
    duration_seconds = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    caller = relationship("User", foreign_keys=[caller_id])


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


def generate_otp_code() -> str:
    return f"{random.randint(0, 999999):06d}"


def hash_otp_code(code: str, email: str) -> str:
    # Salted with the email so identical codes don't hash the same across users.
    return hashlib.sha256(f"{email}:{code}".encode("utf-8")).hexdigest()


def send_otp_email(to_email: str, code: str):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD):
        # SMTP not configured — cannot send email. Caller should handle this.
        raise RuntimeError("SMTP is not configured on the server")

    subject = "Your Secure Chat verification code"
    body = (
        f"Your verification code is: {code}\n\n"
        f"This code expires in {OTP_EXPIRE_MINUTES} minutes. "
        f"If you didn't request this, you can safely ignore this email."
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM, [to_email], msg.as_string())


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
    sender_avatar_url: Optional[str] = None
    receiver_email: str
    text: Optional[str] = None
    file_url: Optional[str] = None
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    is_read: bool
    is_deleted: bool
    is_edited: bool
    created_at: datetime.datetime


class ConversationOut(BaseModel):
    email: str
    username: str
    avatar_url: Optional[str] = None
    last_message: str
    last_time: datetime.datetime
    last_sender_email: str
    last_message_read: bool
    unread_count: int


class UserSearchOut(BaseModel):
    email: str
    username: str
    avatar_url: Optional[str] = None


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str


class SendMessageRequest(BaseModel):
    receiver_email: EmailStr
    text: Optional[str] = None
    file_url: Optional[str] = None
    file_name: Optional[str] = None
    file_type: Optional[str] = None


class EditMessageRequest(BaseModel):
    text: str


class GroupCreateRequest(BaseModel):
    name: str
    member_emails: List[EmailStr]


class GroupMemberOut(BaseModel):
    email: str
    username: str
    avatar_url: Optional[str] = None


class GroupOut(BaseModel):
    id: int
    name: str
    avatar_url: Optional[str] = None
    members: List[GroupMemberOut]
    last_message: Optional[str] = None
    last_time: Optional[datetime.datetime] = None


class GroupMessageSend(BaseModel):
    text: Optional[str] = None
    file_url: Optional[str] = None
    file_name: Optional[str] = None
    file_type: Optional[str] = None


class GroupMessageOut(BaseModel):
    id: int
    group_id: int
    sender_email: str
    sender_username: str
    sender_avatar_url: Optional[str] = None
    text: Optional[str] = None
    file_url: Optional[str] = None
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    is_deleted: bool
    is_edited: bool
    created_at: datetime.datetime


class CallLogCreate(BaseModel):
    callee_email: EmailStr
    is_video: bool
    status: str  # "completed" | "missed" | "busy" | "canceled"
    duration_seconds: int = 0


class CallLogOut(BaseModel):
    id: int
    peer_email: str
    peer_username: str
    peer_avatar_url: Optional[str] = None
    is_video: bool
    status: str
    duration_seconds: int
    direction: str  # "outgoing" | "incoming" relative to the requester
    created_at: datetime.datetime


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
        "avatar_url": current_user.avatar_url,
    }


@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File is too large (max 15MB).")

    ext = os.path.splitext(file.filename or "")[1][:10]
    safe_name = f"{uuid.uuid4().hex}{ext}"
    dest_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(dest_path, "wb") as f:
        f.write(contents)

    file_type = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    return {
        "url": f"/uploads/{safe_name}",
        "file_name": file.filename or safe_name,
        "file_type": file_type,
    }


@app.post("/api/profile/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File is too large (max 15MB).")
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="Avatar must be an image.")

    ext = os.path.splitext(file.filename or "")[1][:10] or ".jpg"
    safe_name = f"avatar_{uuid.uuid4().hex}{ext}"
    dest_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(dest_path, "wb") as f:
        f.write(contents)

    current_user.avatar_url = f"/uploads/{safe_name}"
    db.commit()
    return {"avatar_url": current_user.avatar_url}


@app.post("/api/messages", status_code=201)
def send_message(
    payload: SendMessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not payload.text and not payload.file_url:
        raise HTTPException(status_code=400, detail="Message must have text or a file.")
    recipient = db.query(User).filter(User.email == payload.receiver_email).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    nonce_b64 = ct_b64 = None
    if payload.text:
        nonce_b64, ct_b64 = encrypt_message(payload.text)

    msg = Message(
        sender_id=current_user.id,
        receiver_email=payload.receiver_email,
        nonce=nonce_b64,
        ciphertext=ct_b64,
        file_url=payload.file_url,
        file_name=payload.file_name,
        file_type=payload.file_type,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return {"id": msg.id, "created_at": msg.created_at}


@app.patch("/api/messages/{message_id}")
def edit_message(
    message_id: int,
    payload: EditMessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg or msg.is_deleted:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only edit your own messages")
    nonce_b64, ct_b64 = encrypt_message(payload.text)
    msg.nonce = nonce_b64
    msg.ciphertext = ct_b64
    msg.is_edited = True
    db.commit()
    return {"message": "Message updated"}


@app.delete("/api/messages/{message_id}")
def delete_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own messages")
    msg.is_deleted = True
    msg.nonce = None
    msg.ciphertext = None
    msg.file_url = None
    msg.file_name = None
    msg.file_type = None
    db.commit()
    return {"message": "Message deleted"}


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
        if row.is_deleted:
            text = None
        elif row.ciphertext:
            try:
                text = decrypt_message(row.nonce, row.ciphertext)
            except Exception:
                text = "[unable to decrypt]"
        else:
            text = None
        result.append(
            MessageOut(
                id=row.id,
                sender_email=row.sender.email,
                sender_username=row.sender.username,
                sender_avatar_url=row.sender.avatar_url,
                receiver_email=row.receiver_email,
                text=text,
                file_url=row.file_url,
                file_name=row.file_name,
                file_type=row.file_type,
                is_read=row.is_read,
                is_deleted=row.is_deleted,
                is_edited=row.is_edited,
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
            if last_msg.is_deleted:
                text = "Message deleted"
            elif last_msg.ciphertext:
                text = decrypt_message(last_msg.nonce, last_msg.ciphertext)
            elif last_msg.file_url:
                text = f"📎 {last_msg.file_name or 'File'}"
            else:
                text = ""
        except Exception:
            text = "[unable to decrypt]"
        conversations.append(
            ConversationOut(
                email=partner.email,
                username=partner.username,
                avatar_url=partner.avatar_url,
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
    return [UserSearchOut(email=u.email, username=u.username, avatar_url=u.avatar_url) for u in users]


# ---------------------------------------------------------------------------
# Group chat
# ---------------------------------------------------------------------------
def _require_group_member(group_id: int, user: User, db: Session) -> Group:
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    is_member = (
        db.query(GroupMember)
        .filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id)
        .first()
    )
    if not is_member:
        raise HTTPException(status_code=403, detail="You are not a member of this group")
    return group


def _group_members_out(group_id: int, db: Session) -> List[GroupMemberOut]:
    members = (
        db.query(User)
        .join(GroupMember, GroupMember.user_id == User.id)
        .filter(GroupMember.group_id == group_id)
        .all()
    )
    return [GroupMemberOut(email=m.email, username=m.username, avatar_url=m.avatar_url) for m in members]


@app.post("/api/groups", status_code=201)
def create_group(
    payload: GroupCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    name = payload.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Group name must be at least 2 characters")

    member_emails = {e.strip() for e in payload.member_emails if e.strip()}
    member_emails.add(current_user.email)
    members = db.query(User).filter(User.email.in_(member_emails)).all()
    if len(members) < 2:
        raise HTTPException(status_code=400, detail="Pick at least one other member for the group")

    group = Group(name=name, created_by=current_user.id)
    db.add(group)
    db.commit()
    db.refresh(group)

    for m in members:
        db.add(GroupMember(group_id=group.id, user_id=m.id))
    db.commit()

    return GroupOut(
        id=group.id,
        name=group.name,
        avatar_url=group.avatar_url,
        members=_group_members_out(group.id, db),
        last_message=None,
        last_time=None,
    )


@app.get("/api/groups", response_model=List[GroupOut])
def list_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    my_group_ids = [
        gm.group_id
        for gm in db.query(GroupMember).filter(GroupMember.user_id == current_user.id).all()
    ]
    groups = db.query(Group).filter(Group.id.in_(my_group_ids)).all()

    result = []
    for group in groups:
        last_msg = (
            db.query(GroupMessage)
            .filter(GroupMessage.group_id == group.id)
            .order_by(GroupMessage.created_at.desc())
            .first()
        )
        last_message = None
        last_time = None
        if last_msg:
            last_time = last_msg.created_at
            if last_msg.is_deleted:
                last_message = "Message deleted"
            elif last_msg.ciphertext:
                try:
                    last_message = decrypt_message(last_msg.nonce, last_msg.ciphertext)
                except Exception:
                    last_message = "[unable to decrypt]"
            elif last_msg.file_url:
                last_message = f"📎 {last_msg.file_name or 'File'}"
        result.append(
            GroupOut(
                id=group.id,
                name=group.name,
                avatar_url=group.avatar_url,
                members=_group_members_out(group.id, db),
                last_message=last_message,
                last_time=last_time,
            )
        )
    result.sort(key=lambda g: g.last_time or datetime.datetime.min, reverse=True)
    return result


@app.get("/api/groups/{group_id}/messages", response_model=List[GroupMessageOut])
def get_group_messages(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_group_member(group_id, current_user, db)
    rows = (
        db.query(GroupMessage)
        .filter(GroupMessage.group_id == group_id)
        .order_by(GroupMessage.created_at.asc())
        .all()
    )
    result = []
    for row in rows:
        if row.is_deleted:
            text = None
        elif row.ciphertext:
            try:
                text = decrypt_message(row.nonce, row.ciphertext)
            except Exception:
                text = "[unable to decrypt]"
        else:
            text = None
        result.append(
            GroupMessageOut(
                id=row.id,
                group_id=row.group_id,
                sender_email=row.sender.email,
                sender_username=row.sender.username,
                sender_avatar_url=row.sender.avatar_url,
                text=text,
                file_url=row.file_url,
                file_name=row.file_name,
                file_type=row.file_type,
                is_deleted=row.is_deleted,
                is_edited=row.is_edited,
                created_at=row.created_at,
            )
        )
    return result


@app.post("/api/groups/{group_id}/messages", status_code=201)
def send_group_message(
    group_id: int,
    payload: GroupMessageSend,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_group_member(group_id, current_user, db)
    if not payload.text and not payload.file_url:
        raise HTTPException(status_code=400, detail="Message must have text or a file.")

    nonce_b64 = ct_b64 = None
    if payload.text:
        nonce_b64, ct_b64 = encrypt_message(payload.text)

    msg = GroupMessage(
        group_id=group_id,
        sender_id=current_user.id,
        nonce=nonce_b64,
        ciphertext=ct_b64,
        file_url=payload.file_url,
        file_name=payload.file_name,
        file_type=payload.file_type,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return {"id": msg.id, "created_at": msg.created_at}


@app.patch("/api/groups/{group_id}/messages/{message_id}")
def edit_group_message(
    group_id: int,
    message_id: int,
    payload: EditMessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_group_member(group_id, current_user, db)
    msg = db.query(GroupMessage).filter(GroupMessage.id == message_id, GroupMessage.group_id == group_id).first()
    if not msg or msg.is_deleted:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only edit your own messages")
    nonce_b64, ct_b64 = encrypt_message(payload.text)
    msg.nonce = nonce_b64
    msg.ciphertext = ct_b64
    msg.is_edited = True
    db.commit()
    return {"message": "Message updated"}


@app.delete("/api/groups/{group_id}/messages/{message_id}")
def delete_group_message(
    group_id: int,
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_group_member(group_id, current_user, db)
    msg = db.query(GroupMessage).filter(GroupMessage.id == message_id, GroupMessage.group_id == group_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own messages")
    msg.is_deleted = True
    msg.nonce = None
    msg.ciphertext = None
    msg.file_url = None
    msg.file_name = None
    msg.file_type = None
    db.commit()
    return {"message": "Message deleted"}


@app.post("/api/calls", status_code=201)
def log_call(
    payload: CallLogCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Only the caller's client logs a call, so each call produces exactly one
    # row. The callee sees the same row via the query in get_call_history.
    callee = db.query(User).filter(User.email == payload.callee_email).first()
    if not callee:
        raise HTTPException(status_code=404, detail="Callee not found")
    valid_statuses = {"completed", "missed", "busy", "canceled"}
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid call status")

    log = CallLog(
        caller_id=current_user.id,
        callee_email=callee.email,
        is_video=payload.is_video,
        status=payload.status,
        duration_seconds=max(0, payload.duration_seconds),
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return {"id": log.id, "created_at": log.created_at}


@app.get("/api/calls", response_model=List[CallLogOut])
def get_call_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(CallLog)
        .filter(
            (CallLog.caller_id == current_user.id)
            | (CallLog.callee_email == current_user.email)
        )
        .order_by(CallLog.created_at.desc())
        .limit(200)
        .all()
    )

    result = []
    for row in rows:
        if row.caller_id == current_user.id:
            direction = "outgoing"
            peer = db.query(User).filter(User.email == row.callee_email).first()
        else:
            direction = "incoming"
            peer = row.caller
        if not peer:
            continue
        result.append(
            CallLogOut(
                id=row.id,
                peer_email=peer.email,
                peer_username=peer.username,
                peer_avatar_url=peer.avatar_url,
                is_video=row.is_video,
                status=row.status,
                duration_seconds=row.duration_seconds,
                direction=direction,
                created_at=row.created_at,
            )
        )
    return result


@app.post("/api/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    # Always return a generic success message, regardless of whether the
    # email exists, so we don't leak which emails are registered.
    generic_response = {"message": "If that email is registered, a verification code has been sent."}

    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        return generic_response

    code = generate_otp_code()
    otp = PasswordResetOTP(
        email=payload.email,
        code_hash=hash_otp_code(code, payload.email),
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(minutes=OTP_EXPIRE_MINUTES),
    )
    db.add(otp)
    db.commit()

    try:
        send_otp_email(payload.email, code)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not send verification email. Please try again later or contact support.",
        )

    return generic_response


@app.post("/api/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    otp = (
        db.query(PasswordResetOTP)
        .filter(
            PasswordResetOTP.email == payload.email,
            PasswordResetOTP.used == False,  # noqa: E712
        )
        .order_by(PasswordResetOTP.created_at.desc())
        .first()
    )
    if not otp:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    if otp.expires_at < datetime.datetime.utcnow():
        raise HTTPException(status_code=400, detail="Code has expired. Please request a new one.")
    if otp.code_hash != hash_otp_code(payload.code.strip(), payload.email):
        raise HTTPException(status_code=400, detail="Invalid code")

    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = hash_password(payload.new_password)
    otp.used = True
    db.commit()

    return {"message": "Password has been reset. You can now sign in."}


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
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


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
