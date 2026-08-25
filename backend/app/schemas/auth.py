from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, ConfigDict


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = 1800


class TokenResponse(Token):
    pass


class TokenData(BaseModel):
    user_id: Optional[str] = None
    token_type: Optional[str] = None


class UserBase(BaseModel):
    username: str
    email: EmailStr
    is_active: bool = True


class UserCreate(UserBase):
    password: str
    role_id: Optional[str] = None
    role_name: Optional[str] = "viewer"


class PermissionRead(BaseModel):
    id: str
    code: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)


class RoleRead(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    permissions: List[PermissionRead] = []
    model_config = ConfigDict(from_attributes=True)


class UserRead(UserBase):
    id: str
    role: Optional[RoleRead] = None
    is_superuser: bool = False
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str
