import logging
from functools import wraps
from flask import url_for, redirect, request, Response, abort
from werkzeug.utils import import_string, cached_property
from oauthlib import oauth2
from oauthlib.oauth2 import Server
from flaskr.oauth2.validator import Validator


logger = logging.getLogger('flask_oauth2_server')


def _get_uri_from_request():
    uri = request.base_url
    if request.query_string:
        uri += '?' + request.query_string.decode('utf-8')
    return uri


def _extract_params():
    uri = _get_uri_from_request()
    http_method = request.method
    headers = dict(request.headers)
    if 'wsgi.input' in headers:
        del headers['wsgi.input']
    if 'wsgi.errors' in headers:
        del headers['wsgi.errors']
    if request.authorization:
        headers['Authorization'] = request.authorization
    body = request.form.to_dict()
    return uri, http_method, body, headers


def _create_response(headers, body, status):
    response = Response(body or '')
    for k, v in headers.items():
        response.headers[str(k)] = v
    response.status_code = status
    return response


class Provider:
    def __init__(self, app=None, validator_class=None):
        self._before_request_funcs = []
        self._after_request_funcs = []
        self._exception_handler = None
        self._invalid_response = None
        self._validator_class = validator_class
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['oauth2.provider'] = self

    def _on_exception(self, error, redirect_content=None):
        if self._exception_handler:
            return self._exception_handler(error, redirect_content)
        else:
            return redirect(redirect_content)

    @cached_property
    def error_uri(self):
        if error_uri := self.app.config.get('OAUTH2_PROVIDER_ERROR_URI'):
            return error_uri
        if error_endpoint := self.app.config.get('OAUTH2_PROVIDER_ERROR_ENDPOINT'):
            return url_for(error_endpoint)
        return '/oauth/errors'

    @cached_property
    def server(self):
        expires_in = self.app.config.get(
            'OAUTH2_PROVIDER_TOKEN_EXPIRES_IN'
        )

        token_generator = self.app.config.get(
            'OAUTH2_PROVIDER_TOKEN_GENERATOR',
            None
        )
        if token_generator and not callable(token_generator):
            token_generator = import_string(token_generator)

        refresh_token_generator = self.app.config.get(
            'OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR',
            None
        )
        if refresh_token_generator and not callable(refresh_token_generator):
            refresh_token_generator = import_string(refresh_token_generator)

        if hasattr(self, '_validator'):
            return Server(
                self._validator,
                token_expires_in=expires_in,
                token_generator=token_generator,
                refresh_token_generator=refresh_token_generator,
            )

        if not hasattr(self, '_clientgetter') or \
           not hasattr(self, '_tokengetter') or \
           not hasattr(self, '_tokensetter') or \
           not hasattr(self, '_grantgetter') or \
           not hasattr(self, '_grantsetter'):
            raise RuntimeError('application not bound to required getters')

        usergetter = None
        if hasattr(self, '_usergetter'):
            usergetter = self._usergetter

        validator_class = self._validator_class
        if validator_class is None:
            validator_class = Validator

        validator = validator_class(
            clientgetter=self._clientgetter,
            tokengetter=self._tokengetter,
            grantgetter=self._grantgetter,
            usergetter=usergetter,
            tokensetter=self._tokensetter,
            grantsetter=self._grantsetter,
        )
        self._validator = validator

        return Server(
            validator,
            token_expires_in=expires_in,
            token_generator=token_generator,
            refresh_token_generator=refresh_token_generator,
        )

    def before_request(self, f):
        self._before_request_funcs.append(f)
        return f

    def after_request(self, f):
        self._after_request_funcs.append(f)
        return f

    def exception_handler(self, f):
        self._exception_handler = f
        return f

    def invalid_response(self, f):
        self._invalid_response = f
        return f

    def clientgetter(self, f):
        self._clientgetter = f
        return f

    def usergetter(self, f):
        self._usergetter = f
        return f

    def tokengetter(self, f):
        self._tokengetter = f
        return f

    def tokensetter(self, f):
        self._tokensetter = f
        return f

    def grantgetter(self, f):
        self._grantgetter = f
        return f

    def grantsetter(self, f):
        self._grantsetter = f
        return f

    def authorize_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server
            uri, http_method, body, headers = _extract_params()

            if request.method in ('GET', 'HEAD'):
                redirect_uri = request.args.get('redirect_uri', self.error_uri)
                logger.debug(f'Found redirect_uri {redirect_uri}.')
                try:
                    scopes, credentials = server.validate_authorization_request(
                        uri,
                        http_method,
                        body,
                        headers,
                    )
                    kwargs['scopes'] = scopes
                    kwargs.update(credentials)
                except oauth2.FatalClientError as e:
                    logger.debug(f'Fatal client error {e}', exc_info=True)
                    return self._on_exception(e, e.in_uri(self.error_uri))
                except oauth2.OAuth2Error as e:
                    logger.debug(f'OAuth2Error: {e}', exc_info=True)
                    state = request.values.get('state')
                    if state and not e.state:
                        e.state = state
                    return self._on_exception(e, e.in_uri(redirect_uri))
                except Exception as e:
                    logger.exception(e)
                    return self._on_exception(e, add_params_to_uri(
                        self.error_uri, {'error': str(e)}
                    ))
            else:
                redirect_uri = request.values.get('redirect_uri', self.error_uri)

            try:
                ret = f(*args, **kwargs)
            except oauth2.FatalClientError as e:
                logger.debug(f'Fatal client error {e}', exc_info=True)
                return self._on_exception(e, e.in_uri(self.error_uri))
            except oauth2.OAuth2Error as e:
                logger.debug(f'OAuth2Error: {e}', exc_info=True)
                state = request.values.get('state')
                if state and not e.state:
                    e.state = state
                return self._on_exception(e, e.in_uri(redirect_uri))

            if not isinstance(ret, bool):
                return ret
            if not ret:
                e = oauth2.AccessDeniedError(state=request.values.get('state'))
                return self._on_exception(e, e.in_uri(redirect_uri))
            return self.confirm_authorization_request()

        return decorated

    def confirm_authorization_request(self):
        server = self.server
        scopes = (request.values.get('scope') or '').split()
        credentials = dict(
            client_id=request.values.get('client_id'),
            redirect_uri=request.values.get('redirect_uri', None),
            response_type=request.values.get('response_type', None),
            state=request.values.get('state', None)
        )
        logger.debug(f'Fetched credentials from request {credentials}.')
        redirect_uri = credentials.get('redirect_uri')
        logger.debug('Found redirect_uri {redirect_uri}.')

        uri, http_method, body, headers = _extract_params()
        try:
            ret = server.create_authorization_response(
                uri,
                http_method,
                body,
                headers,
                scopes,
                credentials
            )
            logger.debug('Authorization successful.')
            return _create_response(*ret)
        except oauth2.FatalClientError as e:
            logger.debug(f'Fatal client error {e}', exc_info=True)
            return self._on_exception(e, e.in_uri(self.error_uri))
        except oauth2.OAuth2Error as e:
            log.debug(f'OAuth2Error: {e}', exc_info=True)
            state = request.values.get('state')
            if state and not e.state:
                e.state = state
            return self._on_exception(e, e.in_uri(redirect_uri or self.error_uri))
        except Exception as e:
            logger.exception(e)
            return self._on_exception(e, add_params_to_uri(
                self.error_uri, {'error': str(e)}
            ))

    def verify_request(self, scopes):
        uri, http_method, body, headers = _extract_params()
        return self.server.verify_request(
            uri, http_method, body, headers, scopes
        )

    def token_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server
            uri, http_method, body, headers = _extract_params()
            credentials = f(*args, **kwargs) or {}
            logger.debug(f'Fetched extra credentials, {credentials}.')
            ret = server.create_token_response(
                uri, http_method, body, headers, credentials
            )
            return _create_response(*ret)

        return decorated

    def revoke_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server
            token = request.values.get('token')
            request.token_type_hint = request.values.get('token_type_hint')
            if token:
                request.token = token
            uri, http_method, body, headers = _extract_params()
            ret = server.create_revocation_response(
                uri, headers=headers, body=body, http_method=http_method)
            return _create_response(*ret)

        return decorated

    def require_oauth(self, *scopes):
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                for func in self._before_request_funcs:
                    func()
                if hasattr(request, 'oauth') and request.oauth:
                    return f(*args, **kwargs)
                valid, req = self.verify_request(scopes)
                for func in self._after_request_funcs:
                    valid, req = func(valid, req)
                if not valid:
                    if self._invalid_response:
                        return self._invalid_response(req)
                    return abort(401)
                request.oauth = req
                return f(*args, **kwargs)
            return decorated

        return wrapper
