import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
import jwt
from dotenv import load_dotenv

# Load environment variables if not already loaded
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_file = os.path.join(backend_dir, ".env")
if os.path.exists(env_file):
    load_dotenv(env_file)

SECRET_KEY = os.getenv("JWT_SECRET")

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET environment variable is not configured. Please set JWT_SECRET in your .env file or environment.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7

def validate_password_strength(password: str) -> tuple[bool, str]:
    if not password or len(password.strip()) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit (0-9)."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character (!@#$%^&*)."
    return True, "Password is valid."

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if not salt:
        salt_bytes = os.urandom(16)
        salt = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt)
    
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000)
    return pwd_hash.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    pwd_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(pwd_hash, stored_hash)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS))
    to_encode.update({
        "iat": now,
        "exp": expire
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def sanitize_user(user: dict) -> dict:
    if not user:
        return None
    user_id = str(user.get("_id") or user.get("id") or "")
    full_name = user.get("full_name") or user.get("name") or ""
    return {
        "id": user_id,
        "email": user.get("email", ""),
        "full_name": full_name,
        "name": full_name,
        "scans_remaining": user.get("scans_remaining", 100),
        "created_at": str(user.get("created_at", ""))
    }

def get_current_user_from_token(token: str) -> dict | None:
    from database import users_collection
    from bson import ObjectId
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None
    sub = str(payload["sub"]).strip()
    user = users_collection.find_one({"email": sub.lower()})
    if not user and ObjectId.is_valid(sub):
        user = users_collection.find_one({"_id": ObjectId(sub)})
    return sanitize_user(user)

