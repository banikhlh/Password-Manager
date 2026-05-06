from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime, timezone

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    salt = Column(LargeBinary(16), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    entries = relationship("PasswordEntry", back_populates="user")

class PasswordEntry(Base):
    __tablename__ = "password_entries"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    site = Column(String, nullable=False)
    url = Column(String)
    login = Column(String, nullable=False)
    encrypted_password = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    user = relationship("User", back_populates="entries")