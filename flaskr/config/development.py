from random import choices
from string import printable
from datetime import timedelta


class Development:
    DEBUG = True
    SECRET_KEY = ''.join(choices(printable, k=64))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
