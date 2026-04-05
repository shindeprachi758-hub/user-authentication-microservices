from fastapi import FastAPI, Depends, HTTPException, Body, Request
from sqlalchemy.orm import Session
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Dict
import time

# ========================
# DATABASE SETUP
# ========================
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ========================
# MODELS
# ========================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

Base.metadata.create_all(bind=engine)

# ========================
# SCHEMAS
# ========================
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserProfileUpdate(BaseModel):
    email: EmailStr | None = None
    password: str | None = None

class UserProfileResponse(BaseModel):
    email: EmailStr

# ========================
# AUTHENTICATION / JWT
# ========================
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ========================
# TOKEN BLACKLIST (for revocation)
# ========================
token_blacklist = set()

# ========================
# RATE LIMITING STORAGE
# ========================
# Simple memory-based counter: {user_email: [timestamps]}
rate_limit_store: Dict[str, list] = {}
RATE_LIMIT = 5        # 5 requests
RATE_LIMIT_WINDOW = 60  # per 60 seconds

# ========================
# HELPER FUNCTIONS
# ========================
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if token in token_blacklist:
        raise HTTPException(status_code=401, detail="Token has been revoked")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        # Rate limiting check
        check_rate_limit(email)
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def check_rate_limit(user_email: str):
    now = time.time()
    timestamps = rate_limit_store.get(user_email, [])
    # Remove old timestamps outside the window
    timestamps = [ts for ts in timestamps if now - ts < RATE_LIMIT_WINDOW]
    if len(timestamps) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    timestamps.append(now)
    rate_limit_store[user_email] = timestamps

# ========================
# FASTAPI APP
# ========================
app = FastAPI()

# ========================
# DB DEPENDENCY
# ========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ========================
# TASK 2: REGISTER
# ========================
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = hash_password(user.password)
    new_user = User(email=user.email, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

# ========================
# TASK 3: LOGIN
# ========================
@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email")
    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid password")
    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

# ========================
# TASK 4: TOKEN VALIDATION
# ========================
@app.get("/users/me")
def validate_token(current_user: str = Depends(get_current_user)):
    return {"status": "success", "message": "Token is valid", "user_email": current_user}

# ========================
# TASK 5: USER PROFILE MANAGEMENT
# ========================
@app.get("/users/profile", response_model=UserProfileResponse)
def get_user_profile(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == current_user).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"email": user.email}

@app.put("/users/profile")
def update_user_profile(
    profile: UserProfileUpdate = Body(...),
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == current_user).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if profile.email:
        if db.query(User).filter(User.email == profile.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        user.email = profile.email
    if profile.password:
        user.password = hash_password(profile.password)
    db.commit()
    db.refresh(user)
    return {"message": "Profile updated successfully", "email": user.email}

# ========================
# TASK 6: LOGOUT / TOKEN REVOCATION
# ========================
@app.post("/logout")
def logout(current_user: str = Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    token_blacklist.add(token)
    return {"message": "Logged out successfully. Token revoked."}

# ========================
# OPTIONAL PROTECTED ROUTE
# ========================
@app.get("/protected")
def protected_route(current_user: str = Depends(get_current_user)):
    return {"message": f"Hello {current_user}"}