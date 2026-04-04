from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import engine, SessionLocal

# create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    new_user = models.User(
        email=user.email,
        password=user.password
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully"}