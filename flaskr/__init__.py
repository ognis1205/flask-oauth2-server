import sys
from os import getenv
from pathlib import Path
from flask import Flask


def create_app():
    app = Flask(
        __name__,
        instance_relative_config=True,
    )

    app.config.from_object({
        'development': 'flaskr.config.development.Development',
        'testing': 'flaskr.config.testing.Testing',
        'production': 'flaskr.config.production.Production',
    }[getenv('FLAKS_APP_ENV', default='development')])

    app.config.from_pyfile('config.py')

    from flaskr.models.ext import db, migrate
    db.init_app(app)
    migrate.init_app(app, db)

    return app
