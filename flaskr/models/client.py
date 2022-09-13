from flaskr.models.ext import db


class Client(db.Model):
    __tabelname__ = 'clients'

    __table_args__ = {
        'extend_existing': True,
    }

    client_id = db.Column(db.String(64), primary_key=True)

    client_secret = db.Column(db.String(64), nullable=False)

    user_id = db.Column(db.ForeignKey('user.id'))

    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)

    _default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []
