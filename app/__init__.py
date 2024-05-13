from flask import Flask
from app.routes.auth import auth_bp
from app.models.user_models import db
from app.utils.session import session
from app.utils.bcrypt import bcrypt

app = Flask(__name__)
app.config.from_pyfile('config.py')

db.init_app(app)
with app.app_context():
    db.create_all()

app.register_blueprint(auth_bp)

session.init_app(app)

bcrypt.init_app(app)
