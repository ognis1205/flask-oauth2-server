from functools import cached_property
from flask import url_for, redirect
from oauthlib.oauth2 import Server


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
        expires_in = self.app.config.get('OAUTH2_PROVIDER_TOKEN_EXPIRES_IN')
        token_generator = self.app.config.get(
            'OAUTH2_PROVIDER_TOKEN_GENERATOR', None
        )
        if token_generator and not callable(token_generator):
            token_generator = import_string(token_generator)

        refresh_token_generator = self.app.config.get(
            'OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR', None
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

        if hasattr(self, '_clientgetter') and \
           hasattr(self, '_tokengetter') and \
           hasattr(self, '_tokensetter') and \
           hasattr(self, '_grantgetter') and \
           hasattr(self, '_grantsetter'):

            usergetter = None
            if hasattr(self, '_usergetter'):
                usergetter = self._usergetter

            validator_class = self._validator_class
            if validator_class is None:
                validator_class = OAuth2RequestValidator
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
        raise RuntimeError('application not bound to required getters')
