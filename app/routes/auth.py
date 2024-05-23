from datetime import timedelta, datetime

from flask import Blueprint, render_template, redirect, flash, url_for, session, abort
from itsdangerous import SignatureExpired, BadTimeSignature, BadSignature

from app.models.forms import LoginForm, ResetPasswordForm, RegisterForm, UpdatePasswordForm
from app.helpers.login import login_required
from app.models.user_models import User, db
from app.utils.bcrypt import bcrypt
from app.utils.alex import serializer

auth_bp = Blueprint('auth', __name__)


# app/routes/auth.py

@auth_bp.route('/')
def index():
    user = User.query.first()

    if not user:
        flash('No user found!', 'error')
        return render_template("index.html", reset_url=None)

    token = serializer.dumps(user.email, salt='reset-password')
    reset_url = url_for('auth.reset_password', token=token, _external=True)

    return render_template("index.html", reset_url=reset_url)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        if email and password:
            exist_user = User.query.filter_by(email=email).first()
            if exist_user:
                if bcrypt.check_password_hash(exist_user.password, password):
                    session['user_id'] = exist_user.id
                    session['email'] = exist_user.email
                    flash(f'Welcome back, {exist_user.email}', 'success')
                    return redirect(url_for('auth.index'))
                else:
                    flash('Incorrect email or password', 'error')
            else:
                flash('Incorrect email or password', 'error')
    return render_template('login.html', form=form)


@auth_bp.route('/logout', methods=['GET'])
@login_required
def logout():
    session.clear()
    test = session
    flash('You have been logged out', 'success')
    return redirect(url_for('auth.index'))


@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt='reset-password')
            reset_url = url_for('auth.reset_password_form', token=token, _external=True)
            flash('Password reset link has been sent to your email.', 'success')
            print("Reset URL:", reset_url)  # Print to console for testing
            return redirect(url_for('auth.index'))
        flash('User not found', 'error')
    return render_template('reset_password.html', form=form)


@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_form(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash('The token is invalid or expired.', 'error')
        return redirect(url_for('auth.index'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.index'))

    form = UpdatePasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('update_password.html', form=form, token=token)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(email=form.email.data, password=bcrypt.generate_password_hash(form.password.data))
        db.session.add(new_user)
        db.session.commit()

        flash('You have successfully registered!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)
