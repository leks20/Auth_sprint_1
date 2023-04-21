import logging
import jwt
from jwt.exceptions import ExpiredSignatureError

from http import HTTPStatus
from flasgger import swag_from
from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from conf.config import settings
from db import db
from forms import LoginForm, RegisterForm
from models import LoginHistory, Role, User
from redis_client import redis_client
from flask_wtf.csrf import CSRFProtect

from rate_limit import limit_requests
from utils import create_login_history, email_exists


csrf = CSRFProtect()
auth = Blueprint("auth", __name__)


@auth.route("/register", methods=["POST"])
@swag_from(
    {
        "tags": ["Auth"],
        "parameters": [
            {
                "name": "email",
                "in": "formData",
                "type": "string",
                "required": True
            },
            {
                "name": "password",
                "in": "formData",
                "type": "string",
                "required": True
            }
        ],
        "responses": {
            "200": {
                "description": "Successful"
            },
            "400": {
                "description": "Bad Request"
            }
        }
    }
)
def register():
    """
    Register endpoint
    """
    form = RegisterForm(request.form)

    logging.warning(form.data)

    if request.method == "POST" and "email" in form and "password" in form:
        email = form.email.data
        password = form.password.data
        
        if email_exists(email):
            return (
                jsonify({"status": "error", "message": "Email already in use"}),
                HTTPStatus.BAD_REQUEST,
            )
        
        if not (user_role := Role.query.filter_by(name="user").first()):
            user_role = Role(name="user")
            db.session.add(user_role)
            db.session.commit()

        user = User(email, password)
        user.role = user_role
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return (
                jsonify({"status": "error", "message": "User already exist!"}),
                HTTPStatus.BAD_REQUEST,
            )

        return jsonify({"status": "success"}), HTTPStatus.CREATED

    else:
        return (
            jsonify({"status": "error", "message": "Register failed!"}),
            HTTPStatus.BAD_REQUEST,
        )


@auth.route("/login", methods=["POST"])
@swag_from(
    {
        "tags": ["Auth"],
        "parameters": [
            {
                "name": "email",
                "in": "formData",
                "type": "string",
                "required": True
            },
            {
                "name": "password",
                "in": "formData",
                "type": "string",
                "required": True
            }
        ],
        "responses": {
            "200": {
                "description": "Successful"
            },
            "400": {
                "description": "Bad Request"
            }
        }
    }
)
def login():
    """
    Login endpoint
    """
    form = LoginForm(request.form)

    if request.method == "POST" and "email" in form and "password" in form:
        form_login = form.email.data
        form_password = form.password.data

        if user := User.query.filter_by(email=form_login).first():

            if user.google_id:
                return (
                    jsonify({"status": "error", "message": "Please log in with your Google account."}),
                    HTTPStatus.BAD_REQUEST,
                )
            elif user.verify_password(form_password):
                identity = {"id": user.id, "role": user.role.name}

                access_token = create_access_token(identity=identity, fresh=True)
                refresh_token = create_refresh_token(identity=identity)

                create_login_history(user.id, request)

                return (
                    jsonify(
                        {
                            "access_token": access_token,
                            "refresh_token": refresh_token,
                            "user_id": user.id,
                        }
                    ),
                    HTTPStatus.OK,
                )
            
            else:
                return (
                    jsonify({"status": "error", "message": "Invalid login credentials!"}),
                    HTTPStatus.BAD_REQUEST,
                )

    errors = form.errors.items()
    error_message = "\n".join([f"{param}: {error[0]}" for param, error in errors])
    return (
        jsonify({"status": "error", "message": f"Invalid input: {error_message}"}),
        HTTPStatus.BAD_REQUEST,
    )


@auth.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
@swag_from(
    {
        "tags": ["Auth"],
        "parameters": [
            {
                "name": "Authorization",
                "in": "header",
                "type": "string",
                "required": True,
            },
        ],
        "responses": {
            "200": {
                "description": "Refresh token",
                "schema": {"type": "string"},
            }
        },
    }
)
def refresh():
    """
    Refresh token
    """
    identity = get_jwt_identity()
    user_id=identity["id"]

    if limit_requests(user_id):
        return (
            jsonify({"status": "error", "message": "Too many requests"}),
            HTTPStatus.TOO_MANY_REQUESTS,
        )
    
    access_token = create_access_token(identity=identity, fresh=False)

    return jsonify({"access_token": access_token}), HTTPStatus.OK


@auth.route("/logout", methods=["GET"])
@jwt_required(verify_type=False)
@swag_from(
    {
        "tags": ["Auth"],
        "parameters": [
            {
                "name": "Authorization",
                "in": "header",
                "type": "string",
                "required": True,
            },
        ],
        "responses": {
            "200": {
                "description": "Logout",
                "schema": {"type": "string"},
            }
        },
    }
)
def logout():
    """
    Logout endpoint
    """
    identity = get_jwt_identity()
    user_id=identity["id"]

    if limit_requests(user_id):
        return (
            jsonify({"status": "error", "message": "Too many requests"}),
            HTTPStatus.TOO_MANY_REQUESTS,
        )
    
    token = get_jwt()
    jti = token["jti"]
    ttype = token["type"]
    redis_key = f"jwt_blocklist:{jti}"
    redis_client.set(redis_key, "", ex=settings.access_expires)

    return (
        jsonify(msg=f"{ttype.capitalize()} token successfully revoked"),
        HTTPStatus.OK,
    )


@auth.route("/login_history", methods=["GET"])
@jwt_required()
@swag_from(
    {
        "tags": ["Auth"],
        "parameters": [
            {
                "name": "Authorization",
                "in": "header",
                "type": "string",
                "required": True,
                "description": "Bearer token",
            }
        ],
        "responses": {
            "200": {
                "description": "Returns login history",
                "schema": {"type": "string"},
            }
        },
    }
)
def login_history():
    """
    Login history endpoint
    """
    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=10, type=int)
    identity = get_jwt_identity()
    user_id=identity["id"]

    if limit_requests(user_id):
        return (
            jsonify({"status": "error", "message": "Too many requests"}),
            HTTPStatus.TOO_MANY_REQUESTS,
        )

    history = LoginHistory.query.filter_by(user_id=user_id).paginate(
        page=page, per_page=page_size
    )
    return (
        jsonify(
            {
                "history": [
                    {
                        "user_agent": row.user_agent,
                        "ip_address": row.ip_address,
                        "auth_datetime": row.auth_datetime,
                        "user_device_type": row.user_device_type
                    }
                    for row in history.items
                ],
                "total_pages": history.pages,
                "current_page": history.page,
            }
        ),
        HTTPStatus.OK,
    )


@auth.route("/change_password", methods=["PATCH"])
@jwt_required()
@swag_from(
    {
        "tags": ["Auth"],
        "parameters": [
            {
                "name": "Authorization",
                "in": "header",
                "type": "string",
                "required": True,
            },
            {
                "name": "old_password",
                "in": "formData",
                "type": "string",
                "required": True,
            },
            {
                "name": "new_password",
                "in": "formData",
                "type": "string",
                "required": True,
            },
        ],
        "responses": {
            "200": {
                "description": "Change password",
                "schema": {"type": "string"},
            }
        },
    }
)
def change_password():
    """
    Change password endpoint
    """
    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")

    identity = get_jwt_identity()
    user_id=identity["id"]

    if limit_requests(user_id):
        return (
            jsonify({"status": "error", "message": "Too many requests"}),
            HTTPStatus.TOO_MANY_REQUESTS,
        )
    user = User.query.filter_by(id=user_id).first()
    
    if user is None:
        return jsonify({"message": "User not found."}), HTTPStatus.OK

    if user.verify_password(old_password):
        new_password = generate_password_hash(new_password)
        db.session.query(User).filter_by(id=user.id).update({"password": new_password})
        db.session.commit()
        return jsonify({"message": "Password changed successfully"}), HTTPStatus.OK

    return jsonify({"message": "You entered the wrong old password"}), HTTPStatus.OK


@auth.route("/verify_token", methods=["GET"])
@jwt_required(verify_type=False)
@swag_from(
    {
        "tags": ["Auth"],
        "parameters": [
            {
                "name": "Authorization",
                "in": "header",
                "type": "string",
                "required": True,
            },
    ],
        "responses": {
            "200": {
                "description": "Token is valid",
                "schema": {"type": "string"},
            },
            "401": {
                "description": "Token is invalid or expired",
                "schema": {"type": "string"},
            },
        },
    }
)
def verify_token():
    """
    Verify JWT token endpoint
    """

    token = request.headers.get("Authorization").split(" ")[1]

    try:
        jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except ExpiredSignatureError:
        return jsonify({"message": "Token is expired"}), HTTPStatus.UNAUTHORIZED

    identity = get_jwt_identity()
    user_id=identity["id"]

    if limit_requests(user_id):
        return (
            jsonify({"status": "error", "message": "Too many requests"}),
            HTTPStatus.TOO_MANY_REQUESTS,
        )
    
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User on found"}), HTTPStatus.NOT_FOUND
    
    return jsonify({"message": "Token verified"}), HTTPStatus.OK