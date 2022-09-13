import os
import logging
from datetime import datetime
from flask import request
from oauthlib.oauth2 import RequestValidator


logger = logging.getLogger('flask_oauth2_server')


class Validator(RequestValidator):
    def __init__(
        self,
        clientgetter,
        tokengetter,
        grantgetter,
        usergetter=None,
        tokensetter=None,
        grantsetter=None
    ):
        self._clientgetter = clientgetter
        self._tokengetter = tokengetter
        self._usergetter = usergetter
        self._tokensetter = tokensetter
        self._grantgetter = grantgetter
        self._grantsetter = grantsetter

    def _get_client_creds_from_request(self, request):
        if request.client_id is not None:
            return request.client_id, request.client_secret

        auth = request.headers.get('Authorization')

        if isinstance(auth, dict):
            return auth['username'], auth['password']
        return None, None

    def is_client_authentication_required(self, request, *args, **kwargs):
        def is_confidential(client):
            if hasattr(client, 'is_confidential'):
                return client.is_confidential
            if client_type := getattr(client, 'client_type', None):
                return client_type == 'confidential'
            return True

        grant_types = ('password', 'authorization_code', 'refresh_token')
        client_id, _ = self._get_client_creds_from_request(request)

        if client_id and request.grant_type in grant_types:
            if client := self._clientgetter(client_id):
                return is_confidential(client)
        return False

    def authenticate_client(self, request, *args, **kwargs):
        client_id, client_secret = self._get_client_creds_from_request(request)
        logger.debug(f'Authenticate client {client_id}')

        if client := self._clientgetter(client_id):
            request.client = client
            if hasattr(client, 'client_secret') and client.client_secret != client_secret:
                logger.debug('Authenticate client failed, secret not match.')
                return False
            logger.debug('Authenticate client success.')
            return True

        logger.debug('Authenticate client failed, client not found.')
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        if client_id is None:
            client_id, _ = self._get_client_creds_from_request(request)

        logger.debug(f'Authenticate client {clinet_id}.')
        if client := request.client or self._clientgetter(client_id):
            request.client = client
            return True

        logger.debug('Authenticate failed, client not found.')
        return False

    def confirm_redirect_uri(
        self,
        client_id,
        code,
        redirect_uri,
        client,
        *args,
        **kwargs
    ):
        client = client or self._clientgetter(client_id)

        logger.debug(f'Confirm redirect uri for client {client.client_id} and code {code}.')
        grant = self._grantgetter(client_id=client.client_id, code=code)
        if not grant:
            logger.debug('Grant not found.')
            return False
        if hasattr(grant, 'validate_redirect_uri'):
            return grant.validate_redirect_uri(redirect_uri)

        logger.debug(f'Compare redirect uri for grant {grant.redirect_uri} and {redirect_uri}.')
        if 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ and redirect_uri is None:
            return True

        return grant.redirect_uri == redirect_uri

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        logger.debug('Obtaining scope of refreshed token.')
        return self._tokengetter(refresh_token=refresh_token).scopes

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        if not scopes:
            logger.debug(f'Scope omitted for refresh token {refresh_token}')
            return True

        logger.debug('Confirm scopes {scopes} for refresh token {refresh_token}')
        return set(self._tokengetter(refresh_token=refresh_token).scopes) == set(scopes)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        request.client = request.client or self._clientgetter(client_id)
        redirect_uri = request.client.default_redirect_uri
        logger.debug(f'Found default redirect uri {redirect_uri}')
        return redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        request.client = request.client or self._clientgetter(client_id)
        scopes = request.client.default_scopes
        logger.debug(f'Found default scopes {scopes}')
        return scopes

    def invalidate_authorization_code(
        self,
        client_id,
        code,
        request,
        *args,
        **kwargs
    ):
        logger.debug(f'Destroy grant token for client {client_id}, {code}')
        if grant := self._grantgetter(client_id=client_id, code=code):
            grant.delete()

    def save_authorization_code(
        self,
        client_id,
        code,
        request,
        *args,
        **kwargs
    ):
        logger.debug(f'Persist authorization code {code} for client {client_id}')
        request.client = request.client or self._clientgetter(client_id)
        self._grantsetter(client_id, code, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def save_bearer_token(self, token, request, *args, **kwargs):
        logger.debug(f'Save bearer token {token}')
        self._tokensetter(token, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        logger.debug(f'Validate bearer token {token}')

        if token := self._tokengetter(access_token=token):
            if token.expires is not None and datetime.utcnow() > token.expires:
                request.error_message = 'Bearer token is expired'
                logger.debug(request.error_message)
                return False
            if scopes and not set(token.scopes) & set(scopes):
                request.error_message = 'Bearer token scope not valid'
                logger.debug(request.error_message)
                return False
            request.access_token = token
            request.user = token.user
            request.scopes = scopes
            if hasattr(token, 'client'):
                request.client = token.client
            elif hasattr(token, 'client_id'):
                request.client = self._clientgetter(token.client_id)
            return True

        request.error_message = 'Bearer token not found'
        logger.debug(request.error_message)
        return False

    def validate_client_id(self, client_id, request, *args, **kwargs):
        logger.debug(f'Validate client {client_id}')
        if client := request.client or self._clientgetter(client_id):
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        client = client or self._clientgetter(client_id)
        logger.debug(f'Validate code for client {client.client_id} and code {code}')

        if grant := self._grantgetter(client_id=client.client_id, code=code):
            if hasattr(grant, 'expires') and datetime.utcnow() > grant.expires:
                logger.debug('Grant is expired.')
                return False
            request.state = kwargs.get('state')
            request.user = grant.user
            request.scopes = grant.scopes
            return True

        logger.debug('Grant not found.')
        return False

    def validate_grant_type(
        self,
        client_id,
        grant_type,
        client,
        request,
        *args,
        **kwargs
    ):
        if self._usergetter is None and grant_type == 'password':
            logger.debug('Password credential authorization is disabled.')
            return False

        default_grant_types = (
            'authorization_code',
            'password',
            'client_credentials',
            'refresh_token',
        )

        if hasattr(client, 'allowed_grant_types'):
            if grant_type not in client.allowed_grant_types:
                return False
        else:
            if grant_type not in default_grant_types:
                return False
        if grant_type == 'client_credentials':
            if not hasattr(client, 'user'):
                logger.debug('Client should have a user property')
                return False
            request.user = client.user
        return True

    def validate_redirect_uri(
        self,
        client_id,
        redirect_uri,
        request,
        *args,
        **kwargs
    ):
        request.client = request.client or self._clientgetter(client_id)
        client = request.client
        if hasattr(client, 'validate_redirect_uri'):
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(
        self,
        refresh_token,
        client,
        request,
        *args,
        **kwargs
    ):
        if token := self._tokengetter(refresh_token=refresh_token):
            if token.client_id == client.client_id:
                request.client_id = token.client_id
                request.user = token.user
                return True
            return False

    def validate_response_type(
        self,
        client_id,
        response_type,
        client,
        request,
        *args,
        **kwargs
    ):
        if response_type not in ('code', 'token'):
            return False
        if hasattr(client, 'allowed_response_types'):
            return response_type in client.allowed_response_types
        return True

    def validate_scopes(
        self,
        client_id,
        scopes,
        client,
        request,
        *args,
        **kwargs
    ):
        if hasattr(client, 'validate_scopes'):
            return client.validate_scopes(scopes)
        return set(client.default_scopes).issuperset(set(scopes))

    def validate_user(
        self,
        username,
        password,
        client,
        request,
        *args,
        **kwargs
    ):
        logger.debug(f'Validating username {username} and its password')
        if self._usergetter is not None:
            if user := self._usergetter(
                username,
                password,
                client,
                request,
                *args,
                **kwargs
            ):
                request.user = user
                return True
            return False
        logger.debug('Password credential authorization is disabled.')
        return False

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        if token_type_hint:
            _token = self._tokengetter(**{token_type_hint: token})
        else:
            _token = self._tokengetter(access_token=token)
            if not _token:
                _token = self._tokengetter(refresh_token=token)
        if _token:
            request.client_id = _token.client_id
            request.user = _token.user
            _token.delete()
            return True
        request.error_message = 'Invalid token supplied.'
        logger.debug(request.error_message)
        return False
