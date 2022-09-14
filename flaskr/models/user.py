from flaskr.models.ext import db


class User(db.Model):
    __tablename__ = 'user'

    __table_args__ = {
        'extend_existing': True,
    }

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(64), unique=True)
