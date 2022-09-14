from flaskr.models.ext import db


class Token(db.Model):
    __tabelname__ = 'token'

    __table_args__ = {
        'extend_existing': True,
    }

    id = db.Column(db.Integer, primary_key=True)

    client_id = db.Column(
        db.String(64),
        db.ForeignKey('client.client_id'),
        nullable=False,
    )

    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )

    user = db.relationship('User')

    token_type = db.Column(db.String(64))

    access_token = db.Column(db.String(256), unique=True)

    refresh_token = db.Column(db.String(256), unique=True)

    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []
