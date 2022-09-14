import sys
from os import getenv
from pathlib import Path
from flask import Flask


def create_app():
    app = Flask(
        __name__,
        instance_relative_config=True,
        static_folder='static',
        template_folder='templates',
    )

    app.config.from_object({
        'development': 'flaskr.config.development.Development',
        'testing': 'flaskr.config.testing.Testing',
        'production': 'flaskr.config.production.Production',
    }[getenv('FLAKS_APP_ENV', default='development')])

    app.config.from_pyfile('config.py')

    from flaskr.oauth2.ext import oauth2
    oauth2.init_app(app)

    from flaskr.models.ext import db, migrate
    db.init_app(app)
    migrate.init_app(app, db)

    from flaskr.routes.main import bp as main_blueprint
    app.register_blueprint(main_blueprint)

    from flaskr.routes.oauth import bp as oauth_blueprint
    app.register_blueprint(oauth_blueprint)

    return app
