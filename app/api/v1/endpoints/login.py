# app/api/v1/endpoints/login.py
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from app import schemas
from app.core import security, config
from app.api import deps
from app.crud.crud_user import crud_user
from app.core.security import get_password_hash


router = APIRouter()

@router.post("/access-token", response_model=schemas.Token)
def login_access_token(
    db: Session = Depends(deps.get_db), form_data: OAuth2PasswordRequestForm = Depends()
):
    user = crud_user.authenticate(db, email=form_data.username, password=form_data.password)
    if not user or not crud_user.is_active(user):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires  # Ensure "sub" is email
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/register", response_model=schemas.User)
def register_user(
    *, db: Session = Depends(deps.get_db), user_in: schemas.UserCreate
):
    # Check if the email is already registered
    user = crud_user.get_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400, detail="Email already registered"
        )
    
    user = crud_user.create(db=db, obj_in=user_in)
    return user
