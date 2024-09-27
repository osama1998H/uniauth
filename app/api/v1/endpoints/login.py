from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta

from app import schemas
from app.core import security, config
from app.api import deps
from app.crud.crud_user import crud_user
from app.core.security import verify_password

router = APIRouter()

@router.post("/register", response_model=schemas.User)
def register_user(
    *, db: Session = Depends(deps.get_db), user_in: schemas.UserCreate
):
    user = crud_user.get_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = crud_user.create(db=db, obj_in=user_in)
    return user

@router.post("/access-token", response_model=schemas.Token)
def login_access_token(
    db: Session = Depends(deps.get_db), form_data: OAuth2PasswordRequestForm = Depends()
):
    user = crud_user.authenticate(db, email=form_data.username, password=form_data.password)
    if not user or not crud_user.is_active(user):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/password-reset/request", response_model=dict)
def request_password_reset(
    *, db: Session = Depends(deps.get_db), email: schemas.PasswordResetRequest
):
    user = crud_user.get_by_email(db, email=email.email)
    if not user:
        raise HTTPException(status_code=400, detail="Email not registered")
    reset_token = security.create_access_token(data={"sub": user.email})
    return {"message": "Password reset link sent", "reset_token": reset_token}

@router.post("/password-reset/confirm", response_model=dict)
def confirm_password_reset(
    *, db: Session = Depends(deps.get_db), body: schemas.PasswordResetConfirm
):
    user = crud_user.get_by_email(db, email=body.email)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email")
    payload = security.decode_access_token(body.token)
    if not payload or payload["sub"] != user.email:
        raise HTTPException(status_code=400, detail="Invalid reset token or token does not match email")
    user = crud_user.update_password(db=db, user=user, new_password=body.new_password)
    return {"message": "Password updated successfully"}

@router.put("/password/update", response_model=schemas.User)
def update_password(
    *,
    db: Session = Depends(deps.get_db),
    current_user: schemas.User = Depends(deps.get_current_active_user),
    user_in: schemas.UserUpdatePassword
):
    if not verify_password(user_in.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect old password")
    user = crud_user.update_password(db=db, user=current_user, new_password=user_in.new_password)
    return user
