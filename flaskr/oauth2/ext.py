import datetime
from datetime import timedelta
from flask import request
from flaskr.oauth2.provider import Provider
from flaskr.models import Client, Grant, Token
from flaskr.models.ext import db


oauth2 = Provider()


@oauth2.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth2.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth2.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),
        expires=datetime.utcnow() + timedelta(seconds=100),
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth2.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth2.tokensetter
def save_token(token, request, *args, **kwargs):
    founds = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )

    for found in founds:
        db.session.delete(found)

    token = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=datetime.utcnow() + timedelta(seconds=token.pop('expires_in')),
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(token)
    db.session.commit()
    return token
