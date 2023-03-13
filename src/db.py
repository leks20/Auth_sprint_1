from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

from conf.config import settings

db = SQLAlchemy()


def init_db(app: Flask):
    app.config["SQLALCHEMY_DATABASE_URI"] = settings.sqlalchemy_database_uri
    app.app_context().push()

    db.init_app(app)
    migrate = Migrate(app, db)  # NOQA F402
