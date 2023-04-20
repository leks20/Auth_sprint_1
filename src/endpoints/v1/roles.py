from http import HTTPStatus

from flask import Blueprint, jsonify, request
from sqlalchemy.exc import IntegrityError
from flasgger import swag_from

from db import db
from models import Role
from utils import admin_required

roles = Blueprint("roles", __name__)


# Get all roles
@roles.route("/", methods=["GET"])
@admin_required()
@swag_from(
    {
        "tags": ["Roles"],
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
                "description": "Get roles",
                "schema": {"type": "string"},
            }
        },
    }
)
def get_roles():
    roles = Role.query.all()
    return jsonify([{"id": role.id, "name": role.name} for role in roles])


# Get a specific role by ID
@roles.route("/<int:role_id>", methods=["GET"])
@admin_required()
@swag_from(
    {
        "tags": ["Roles"],
        "parameters": [
            {
                "name": "Authorization",
                "in": "header",
                "type": "string",
                "required": True,
            },
            {
                "name": "role_id",
                "in": "path",
                "type": "string",
                "required": "true",
            },
        ],
        "responses": {
            "200": {
                "description": "Get role by id",
                "schema": {"type": "string"},
            }
        },
    }
)
def get_role(role_id):
    role = Role.query.get_or_404(role_id)
    return jsonify({"id": role.id, "name": role.name})


# Create a new role
@roles.route("/", methods=["POST"])
@admin_required()
@swag_from(
    {
        "tags": ["Roles"],
        "parameters": [
            {
                "name": "Authorization",
                "in": "header",
                "type": "string",
                "required": True,
            },
            {
                "name": "name",
                "in": "formData",
                "type": "string",
                "required": "true",
            },
        ],
        "responses": {
            "200": {
                "description": "Create role",
                "schema": {"type": "string"},
            }
        },
    }
)
def create_role():
    role_name = request.form.get("name")

    if not role_name:
        return jsonify({"error": "Role name is required"}), HTTPStatus.BAD_REQUEST
    role = Role(name=role_name)
    db.session.add(role)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Role already exists"}), HTTPStatus.BAD_REQUEST
    return jsonify({"id": role.id, "name": role.name}), HTTPStatus.CREATED


# Update a role
@roles.route("/change_name", methods=["PUT"])
@admin_required()
@swag_from(
    {
        "tags": ["Roles"],
        "parameters": [
            {
                "name": "Authorization",
                "in": "header",
                "type": "string",
                "required": True,
            },
            {
                "name": "role_id",
                "in": "formData",
                "type": "string",
                "required": "true",
            },
            {
                "name": "new_name",
                "in": "formData",
                "type": "string",
                "required": "true",
            },
        ],
        "responses": {
            "200": {
                "description": "Update role",
                "schema": {"type": "string"},
            }
        },
    }
)
def update_role():
    role_id = request.form.get("role_id")
    new_name = request.form.get("new_name")

    role = Role.query.get_or_404(role_id)
    if not new_name:
        return jsonify({"error": "Role name is required"}), HTTPStatus.BAD_REQUEST
    role.name = new_name
    db.session.commit()
    return jsonify({"id": role.id, "name": role.name}), HTTPStatus.OK


# Delete a role
@roles.route("/<int:role_id>", methods=["DELETE"])
@admin_required()
@swag_from(
    {
        "tags": ["Roles"],
        "parameters": [
            {
                "name": "Authorization",
                "in": "header",
                "type": "string",
                "required": True,
            },
            {
                "name": "role_id",
                "in": "path",
                "type": "string",
                "required": "true",
            },
        ],
        "responses": {
            "200": {
                "description": "Delete role",
                "schema": {"type": "string"},
            }
        },
    }
)
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)
    db.session.delete(role)
    db.session.commit()
    return jsonify({"message": "Role deleted successfully"}), HTTPStatus.OK
