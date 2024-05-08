from flask import Blueprint, render_template, request, redirect, flash, url_for, session
from app.models.forms import LoginForm, ResetPasswordForm, RegisterForm
from app.models.user_models import User, db  # Добавлен импорт класса User

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/')
def index():
    return render_template('index.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        remember_me = form.remember_me.data

        # Здесь может быть ваша логика аутентификации

    return render_template('login.html', form=form)


@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # Логика сброса пароля
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(form.email.data, form.password.data)
        db.session.add(user)
        db.session.commit()
        # Добавление сессий
        session['email'] = form.email.data
        return redirect(url_for('login'))
    return render_template('register.html', form=form)
