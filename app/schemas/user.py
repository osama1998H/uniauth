# app/schemas/user.py
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    email: EmailStr = Field(None, description="The user's email address")

class UserCreate(UserBase):
    password: str

class UserUpdate(UserBase):
    full_name: str = Field(None, description="The user's full name")
    password: str = Field(None, description="The user's new password")

class UserInDBBase(UserBase):
    id: int
    is_active: bool
    is_superuser: bool

    class Config:
        from_attributes = True

class User(UserInDBBase):
    pass

class UserInDB(UserInDBBase):
    hashed_password: str

