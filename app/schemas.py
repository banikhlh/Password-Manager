from pydantic import BaseModel
from typing import Optional

class UserRegister(BaseModel):
    username: str
    password: str

class EntryCreate(BaseModel):
    site: str
    url: Optional[str] = None
    login: str
    password: str
    master_pw: str
    extra_key: str

class EntryUpdate(BaseModel):
    site: str
    url: Optional[str] = None
    login: str
    password: str
    master_pw: str
    extra_key: str

class DecryptRequest(BaseModel):
    master_pw: str
    extra_key: str