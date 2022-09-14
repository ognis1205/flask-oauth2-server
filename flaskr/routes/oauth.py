from flask import Blueprint, request, redirect, render_template, jsonify
from flaskr.models import User
from flaskr.oauth2.ext import oauth2


bp = Blueprint('auth', __name__)


@bp.route('/oauth/token', methods=['GET', 'POST'])
@oauth2.token_handler
def access_token():
    return None


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth2.authorize_handler
def authorize(*args, **kwargs):
    if user := current_user():
        if request.method == 'GET':
            client_id = kwargs.get('client_id')
            client = Client.query.filter_by(client_id=client_id).first()
            kwargs['client'] = client
            kwargs['user'] = user
            return render_template('oauth/authorize.html', **kwargs)
        confirm = request.form.get('confirm', 'no')
        return confirm == 'yes'
    return redirect('/')


@bp.route('/api/profile')
@oauth2.require_oauth()
def profile():
    return jsonify(username=request.oauth.user.username)
