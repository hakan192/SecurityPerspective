from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core_db import get_db
from app.core_security import create_token, verify_password
from app.models import User

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/token")
def token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username, User.is_active.is_(True)).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    return {"access_token": create_token(user.username, user.role.value), "token_type": "bearer", "role": user.role.value}
