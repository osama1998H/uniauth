# app/schemas/user.py
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str
    full_name: str

class UserUpdate(UserBase):
    full_name: Optional[str]
    password: Optional[str]

class UserUpdatePassword(BaseModel):
    old_password: str
    new_password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    email: EmailStr

class UserInDBBase(UserBase):
    id: int
    is_active: bool
    is_superuser: bool

    model_config = {
        "from_attributes": True
    }

class User(UserInDBBase):
    pass

class UserInDB(UserInDBBase):
    hashed_password: str
