import hashlib, hmac, os, re, secrets, uuid
from config import PASSWORD_MIN_LENGTH

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{4,30}$")
EMAIL_RE = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$")

def normalize_username(value): return value.strip().casefold()
def normalize_email(value): return value.strip().casefold()
def new_user_id(): return "USR-" + secrets.token_hex(6).upper()
def new_record_id(prefix): return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"

def validate_username(value):
    value=value.strip()
    if not USERNAME_RE.fullmatch(value):
        raise ValueError("Username must be 4–30 characters using letters, numbers, period, underscore, or hyphen.")
    return value

def validate_email(value):
    value=value.strip()
    if len(value)>254 or not EMAIL_RE.fullmatch(value): raise ValueError("Please enter a valid email address.")
    return value

def validate_password(value):
    if len(value) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must contain at least {PASSWORD_MIN_LENGTH} characters.")
    if len(value) > 128:
        raise ValueError("Password cannot exceed 128 characters.")
    if not any(c.isalpha() for c in value) or not any(c.isdigit() for c in value):
        raise ValueError("Password must include at least one letter and one number.")
    return value

def hash_password(password):
    validate_password(password); salt=os.urandom(16); digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"

def verify_password(password, encoded):
    try:
        kind,n,r,p,salt_hex,digest_hex=encoded.split("$")
        if kind!="scrypt": return False
        actual=hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt_hex),n=int(n),r=int(r),p=int(p))
        return hmac.compare_digest(actual,bytes.fromhex(digest_hex))
    except (ValueError,TypeError): return False
