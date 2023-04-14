import uuid

from datetime import datetime
from sqlalchemy import UniqueConstraint

from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import text

from db import db


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        {
            'postgresql_partition_by': 'HASH (id)',
        }
    )
    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    email = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(250), nullable=False)

    role_id = db.Column(db.Integer, db.ForeignKey("role.id", ondelete="CASCADE"))
    role = relationship("Role", back_populates="user")

    login_histories = relationship(
        "LoginHistory", back_populates="user", passive_deletes=True
    )

    def __init__(self, email, password):
        self.email = email
        self.password = generate_password_hash(password)

    def __str__(self):
        return f"<User {self.email}>"

    def __repr__(self):
        return f"<User.email={self.email},User.id={self.id}>"

    def verify_password(self, pwd):
        return check_password_hash(self.password, pwd)

    def is_active(self):
        return True

    def get_id(self):
        return self.id

    def is_anonymous(self):
        return False


class LoginHistory(db.Model):
    """Модель для истории входов в аккаунт пользователя"""

    __tablename__ = "login_history"
    __table_args__ = (
        {
            'postgresql_partition_by': 'LIST (user_device_type)',
        }
    )

    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    user_id = db.Column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    user = relationship("User", back_populates="login_histories", passive_deletes=True)
    user_agent = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(80), nullable=True)
    auth_datetime = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    user_device_type = db.Column(db.Text, primary_key=True)


    def __repr__(self):
        return f"LoginHistory: {self.user_agent} - {self.auth_datetime}"

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    user = relationship("User", back_populates="role", passive_deletes=True)

    def __repr__(self):
        return f"<Role {self.name}>"
