from itsdangerous import URLSafeTimedSerializer
from app.config import SECRET_KEY

serializer = URLSafeTimedSerializer(SECRET_KEY)
