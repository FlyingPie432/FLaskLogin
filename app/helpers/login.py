from functools import wraps
from flask import session, redirect, url_for
from app.models.user_models import User


def login_required(func):
    @wraps(func)
    def login_check(*args, **kwargs):
        if 'email' in session:
            user = User.query.filter_by(email=session['email']).first()
            if user:
                result = func(*args, **kwargs)
                return result
        return redirect(url_for('auth.login'))

    return login_check
