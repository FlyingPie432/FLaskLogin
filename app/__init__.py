from flask import Flask

app = Flask(__name__)
app.config.from_pyfile('config.py')

from app.routes.auth import auth_bp
app.register_blueprint(auth_bp)

from app.models.user_models import db
db.init_app(app)
with app.app_context():
    db.create_all()

from app.utils.session import session
session.init_app(app)

from app.utils.bcrypt import bcrypt
bcrypt.init_app(app)