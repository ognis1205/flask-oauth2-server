from random import choices
from string import printable
from datetime import timedelta


class Production:
    DEBUG = False
    SECRET_KEY = ''.join(choices(printable, k=64))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
