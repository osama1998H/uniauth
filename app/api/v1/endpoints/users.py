# app/api/v1/endpoints/users.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import schemas
from app.api import deps
from app.crud.crud_user import crud_user

router = APIRouter()

@router.post("/", response_model=schemas.User)
def create_user(*, db: Session = Depends(deps.get_db), user_in: schemas.UserCreate):
    user = crud_user.get_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = crud_user.create(db=db, obj_in=user_in)
    return user

@router.get("/me", response_model=schemas.User)
def read_user_me(current_user: schemas.User = Depends(deps.get_current_user)):
    return current_user
