import db
from endpoints.v1.auth import auth
from endpoints.v1.roles import roles
from flasgger import Swagger
from flask import Flask, request
from gevent import monkey
from flask_jwt_extended import JWTManager
from conf.config import settings
from tracer import configure_tracer
from opentelemetry.instrumentation.flask import FlaskInstrumentor


monkey.patch_all()

jwt = JWTManager()
swagger = Swagger()


def create_app():
    configure_tracer()
    app = Flask(__name__)
    FlaskInstrumentor().instrument_app(app)
    app.debug = True

    @app.before_request
    def before_request():
        request_id = request.headers.get('X-Request-Id')
        if not request_id:
            raise RuntimeError('Request id is required') 

    db.init_db(app)
    jwt.init_app(app)
    swagger.init_app(app)

    app.register_blueprint(auth, url_prefix="/auth")
    app.register_blueprint(roles, url_prefix="/roles")

    app.config["SECRET_KEY"] = settings.secret_key
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = settings.access_expires
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = settings.refresh_expires
    app.config["JWT_BLACKLIST_ENABLED"] = True
    app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access", "refresh"]
    return app

app = create_app()
