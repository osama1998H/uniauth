# app/api/v1/endpoints/users.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import schemas
from app.api import deps
from app.crud.crud_user import crud_user
from app.schemas.user import User, UserUpdate


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


@router.put("/me", response_model=User)
async def update_user_profile(
    *,
    db: Session = Depends(deps.get_db),
    user_in: UserUpdate,
    current_user: User = Depends(deps.get_current_active_user)
):
    """
    Update own user profile.

    This endpoint allows the current authenticated user to update their profile information.
    """
    user = crud_user.update(db, db_obj=current_user, obj_in=user_in)
    return user
