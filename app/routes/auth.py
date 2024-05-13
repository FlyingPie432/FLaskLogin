from datetime import timedelta, datetime

from flask import Blueprint, render_template, redirect, flash, url_for, session, abort
from itsdangerous import SignatureExpired, BadTimeSignature

from app.models.forms import LoginForm, ResetPasswordForm, RegisterForm
from app.helpers.login import login_required
from app.models.user_models import User, db
from app.utils.bcrypt import bcrypt
from app.utils.alex import serializer

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/')
def index():
    user = User.query.filter_by(id=1).first()
    token = serializer.dumps(user.email, salt='reset-password')
    reset_url = url_for('auth.reset_password_success', token=token, _external=True)
    # Imitation of sending prosess to email
    print(reset_url)
    return render_template("index.html")

    # if 'email' in session:
    #     return render_template('index.html', message='Вы уже зарегистрировались.')
    # return render_template('index.html')


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


from flask import redirect


@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    reset_password_link = None
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt='reset-password')
            reset_url = url_for('auth.reset_password_success', token=token, _external=True)
            flash('Password reset link has been sent to your email.', 'success')
            return redirect(
                url_for('auth.index'))  # Перенаправляем на главную страницу после отправки ссылки на сброс пароля
        flash('User not found', 'error')
    return render_template('reset_password.html', form=form, reset_password_link=reset_password_link)


@auth_bp.route("/reset_password/<string:token>")
def reset_password_success(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        abort(404)

    user = User.query.filter_by(email=email).first()

    if not user:
        abort(404)

    return f"Password reset successful for {user.email}."

    print(user)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # existing_user = User.query.filter_by(email=form.email.data).first()
        # if existing_user:
        #     flash('User with this email already exists.', 'error')
        #     return redirect(url_for('auth.register'))
        new_user = User(email=form.email.data, password=bcrypt.generate_password_hash(form.password.data))
        db.session.add(new_user)
        db.session.commit()

        flash('You have successfully registered!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)
