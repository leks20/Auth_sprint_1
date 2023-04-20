import json
from sqlalchemy.exc import IntegrityError
import pytest

from app import create_app
from models import Role, User
from db import db


@pytest.fixture(scope="session")
def client():
    app = create_app()

    with app.test_client() as client:
        yield client


@pytest.fixture(scope="session", autouse=True)
def admin():
    if not (admin_role := Role.query.filter_by(name="admin").first()):
        admin_role = Role(name="admin")
        db.session.add(admin_role)
        db.session.commit()

    user = User("admin@test.com", "test_password")
    user.role = admin_role
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()


@pytest.fixture(scope="session")
def access_token(client):
    response_login = client.post(
        "/auth/login",
        data={"email": "admin@test.com", "password": "test_password"},
    )
    return json.loads(response_login.data)["access_token"]
