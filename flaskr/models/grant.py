from flaskr.models.ext import db


class Grant(db.Model):
    __tabelname__ = 'grant'

    __table_args__ = {
        'extend_existing': True,
    }

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))

    user = db.relationship('User')

    client_id = db.Column(
        db.String(64), db.ForeignKey('client.client_id'),
        nullable=False,
    )

    client = db.relationship('Client')

    code = db.Column(db.String(256), index=True, nullable=False)

    redirect_uri = db.Column(db.String(256))

    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []
