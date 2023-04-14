from functools import wraps
from flask_jwt_extended import verify_jwt_in_request
from http import HTTPStatus
import click
from flask import jsonify
from flask.cli import AppGroup
from flask_jwt_extended import get_jwt
from sqlalchemy.exc import IntegrityError

from db import db
from models import Role, User


superuser_cli = AppGroup("user")


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["sub"]["role"] == "admin":
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Admins only!"), HTTPStatus.FORBIDDEN

        return decorator

    return wrapper


@superuser_cli.command("create-superuser")
@click.option("--email", prompt="Input email:")
@click.option("--password", prompt="Input password:", hide_input=True)
def create_superuser(email, password):
    """
    Create a superuser
    ---
    responses:
      200:
        description: Successful
    parameters:
      - name: email
        in: path
        type: string
        required: true
      - name: password
        in: path
        type: string
        required: true

    """

    if not (admin_role := Role.query.filter_by(name="admin").first()):
        admin_role = Role(name="admin")
        db.session.add(admin_role)
        db.session.commit()

    user = User(email, password)
    user.role = admin_role
    db.session.add(user)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return (
            jsonify({"status": "error", "message": "User already exists!"}),
            HTTPStatus.BAD_REQUEST,
        )


def email_exists(email):
    existing_user = User.query.filter_by(email=email).first()
    return existing_user is not None