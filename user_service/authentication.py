from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
import jwt

class StatelessJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth = request.headers.get('Authorization')
        if not auth or not auth.startswith('Bearer '):
            return None
        try:
            token   = auth.split(' ')[1]
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=['HS256']
            )
        except Exception:
            return None  # let next authenticator try

        # Only handle if user_id doesn't exist in DB (internal service token)
        from django.contrib.auth.models import User
        user_id = payload.get('user_id')
        try:
            User.objects.get(pk=user_id)
            return None  # real user exists → let JWTAuthentication handle it
        except (User.DoesNotExist, ValueError, TypeError):
            # Internal token — return StatelessUser
            return (StatelessUser(payload), token)


class StatelessUser:
    def __init__(self, payload):
        self._payload         = payload
        self.is_authenticated = True
        self.is_active        = True
        self.is_staff         = 'Administrator' in payload.get('groups', [])
        self.username         = payload.get('username', '')
        self.id               = payload.get('user_id', 0)

    def get(self, key, default=None):
        return self._payload.get(key, default)

    def __getitem__(self, key):
        return self._payload[key]