from flask import Blueprint, request, session, redirect, render_template, jsonify
from werkzeug.security import gen_salt
from flaskr.models import User, Client
from flaskr.models.ext import db
from flaskr.oauth2.ext import oauth2
from flaskr.routes.utils import current_user


bp = Blueprint('main', __name__)


@bp.route('/', methods=('GET', 'POST'))
def index():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect('/')
    return render_template('main/index.html', user=current_user())


@bp.route('/client')
def client():
    if user := current_user():
        item = Client(
            client_id=gen_salt(40),
            client_secret=gen_salt(50),
            _redirect_uris=' '.join([
                'http://localhost:8000/authorized',
                'http://127.0.0.1:8000/authorized',
                'http://127.0.1:8000/authorized',
                'http://127.1:8000/authorized',
            ]),
            _default_scopes='email',
            user_id=user.id,
        )
        db.session.add(item)
        db.session.commit()
        return jsonify(
            client_id=item.client_id,
            client_secret=item.client_secret,
        )
    return redirect('/')
