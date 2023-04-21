from http import HTTPStatus
from flask import redirect, request, jsonify, url_for, Blueprint, session
from google_auth_oauthlib.flow import Flow
from google.oauth2 import credentials as google_credentials

from flasgger import swag_from
import requests
from models import Role, User
from db import db
import jwt
from utils import create_login_history, credentials_to_dict, email_exists

google = Blueprint("google", __name__)


@google.route("/", methods=["GET"])
@swag_from(
    {
        "tags": ["Auth"],
        "responses": {
            "200": {
                "description": "URL for redirect to Google's consent page"
            }
        }
    }
)
def google_auth():
    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]
    )
    
    flow.redirect_uri = url_for('google.auth_callback', _external=True)

    authorization_url, state = flow.authorization_url(
        prompt='consent',
        access_type='offline',
        include_granted_scopes='true'
    )
    
    session['state'] = state

    return jsonify({"message": "Redirect to Google's consent page", "redirect_url": authorization_url}), HTTPStatus.OK


@google.route("/auth_callback", methods=["GET"])
@swag_from(
    {
        "tags": ["Auth"],
        "responses": {
            "200": {
                "description": "Authentication successful"
            },
            "400": {
                "description": "Bad Request"
            }
        }
    }
)
def auth_callback():

    state = session['state']

    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"       ],
        state=state
    )   

    flow.redirect_uri = url_for('google.auth_callback', _external=True)

    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    decoded_id_token = jwt.decode(credentials.id_token, options={"verify_signature": False})

    email = decoded_id_token["email"]
    google_id = decoded_id_token["sub"]

    if not email_exists(email):
        if not (user_role := Role.query.filter_by(name="user").first()):
            user_role = Role(name="user")
            db.session.add(user_role)
            db.session.commit()
        user = User(
            email=email,
            password=None,
            google_id=google_id,
        )
        user.role = user_role
        db.session.add(user)
        db.session.commit()
    else:
        user = User.query.filter_by(email=email).first()
    
    create_login_history(user.id, request)

    return jsonify(
       {"message": "Authentication successful", "email": email}, HTTPStatus.OK)

@google.route('/revoke', methods=["GET"])
@swag_from(
    {
        "tags": ["Auth"],
        "responses": {
            "200": {
                "description": "Credentials successfully revoked"
            },
            "400": {
                "description": "Bad Request"
            }
        }
    }
)
def revoke():
  if 'credentials' not in session:
    return jsonify(
       {"message": "You need to authorize to revoke credentials"},
        HTTPStatus.BAD_REQUEST
       )

  credentials = google_credentials.Credentials(
    **session['credentials'])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')

  if status_code == 200:
    return jsonify({"message": "Credentials successfully revoked"}, HTTPStatus.OK)
  else:
    return jsonify({"message": "An error occurred"}, HTTPStatus.OK)