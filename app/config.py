import os
from datetime import timedelta
from pathlib import Path

SECRET_KEY = os.urandom(16)
path = Path(__file__).parent.absolute()
SQLALCHEMY_DATABASE_URI = f'sqlite:///{path}/db/flask.db'

SESSION_FILE_DIR = f'{path}/sessions'
SESSION_TYPE = 'filesystem'
# SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
REMEMBER_COOKIE_DURATION = 3600
SESSION_PERMANENT = True
PERMANENT_SESSION_LIFETIME = timedelta(days=7)