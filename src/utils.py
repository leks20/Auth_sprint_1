from functools import wraps
from flask_jwt_extended import verify_jwt_in_request
from http import HTTPStatus
import click
from flask import jsonify
from flask.cli import AppGroup
from flask_jwt_extended import get_jwt
from sqlalchemy.exc import IntegrityError
from user_agents import parse
from flask import request

from db import db
from models import LoginHistory, Role, User


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


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def create_login_history(user_id: str, request: request) -> None:
    user_agent_string = request.headers.get("user-agent", "")
    user_agent_parsed = parse(user_agent_string)

    if user_agent_parsed.is_mobile:
        user_device_type = "mobile"
    elif user_agent_parsed.is_tablet:
        user_device_type = "tablet"
    elif user_agent_parsed.is_pc:
        user_device_type = "web"
    else:
        user_device_type = "other"

    user_host = request.headers.get("host", "")

    user_info = LoginHistory(
        user_id=user_id,
        user_agent=user_agent_string,
        ip_address=user_host,
        user_device_type=user_device_type,

    )
    db.session.add(user_info)
    db.session.commit()