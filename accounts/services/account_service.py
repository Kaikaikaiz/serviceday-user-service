from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Group
from django.core import signing


from user_service import settings
import requests
import re

class AccountService:

    RESET_SALT    = "password-reset"
    RESET_TIMEOUT = 3600    # 1 hour in seconds

    @staticmethod
    def validate_registration(username, email, password1, password2):
        # ── Field presence ──────────────────────────────────────
        if not all([username, email, password1, password2]):
            return "All fields are required."

        # ── Username rules ──────────────────────────────────────
        if len(username) < 3:                               # NEW: min length
            return "Username must be at least 3 characters."
        if len(username) > 150:
            return "Username must be 150 characters or fewer."
        if ' ' in username:                                 # NEW: no spaces
            return "Username cannot contain spaces."

        # ── Email format ────────────────────────────────────────
        email_regex = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'       # NEW: format check
        if not re.match(email_regex, email):
            return "Enter a valid email address."

        # ── Password rules ──────────────────────────────────────
        if password1 != password2:
            return "Passwords do not match."
        if not password1.strip():                           # NEW: whitespace-only
            return "Password cannot be blank or whitespace."
        if len(password1) < 8:
            return "Password must be at least 8 characters."
        if not any(c.isupper() for c in password1):
            return "Password must contain at least one uppercase letter."
        if not any(c.isdigit() for c in password1):
            return "Password must contain at least one number."

        # ── Uniqueness checks ───────────────────────────────────
        if User.objects.filter(username__iexact=username).exists():  # FIX: case-insensitive
            return "Username already taken."
        if User.objects.filter(email=email).exists():
            return "Email already registered."

        return None

    @staticmethod
    def register_user(username, email, first_name, last_name, password):
        from django.contrib.auth.models import User, Group
        from django.core import signing

        # is_active=False — cannot login until email verified
        user = User.objects.create_user(
            username   = username,
            email      = email,
            first_name = first_name,
            last_name  = last_name,
            password   = password,
            is_staff   = False,
            is_active  = False,       # ← CHANGED
        )

        employee_group, _ = Group.objects.get_or_create(name="Employee")
        user.groups.add(employee_group)

        # generate verification token (reuse same signing mechanism)
        token = signing.dumps(user.pk, salt='email-verification')

        # build verification URL pointing to gateway
        gateway_url      = getattr(settings, 'GATEWAY_URL')
        verification_url = f"{gateway_url}/verify-email/{token}/"

        import logging
        logger = logging.getLogger(__name__)

        # In register_user, replace the try/except:
        try:
            response = requests.post(
                settings.NOTIFICATION_SERVICE_URL + '/api/v1/notifications/send-verification/',
                json={
                    'email':            email,
                    'name':             first_name or username,
                    'verification_url': verification_url,
                },
                timeout=5,
            )
            logger.info(f"Notification response: {response.status_code} {response.text}")
        except Exception as e:
            logger.error(f"Failed to send verification email: {e}")  # ← This will show you the real error

        return user

    #— session rotation on login ────────
    @staticmethod
    def login_user(request, username, password):
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            request.session.cycle_key()  # prevents session fixation
        return user

    @staticmethod
    def logout_user(request):
        logout(request)

    @staticmethod
    def generate_reset_token(user):
        return signing.dumps(user.pk, salt=AccountService.RESET_SALT)

    @staticmethod
    def resolve_reset_token(token):
        try:
            user_pk = signing.loads(
                token,
                salt    = AccountService.RESET_SALT,
                max_age = AccountService.RESET_TIMEOUT,
            )
            return User.objects.get(pk=user_pk)
        except (signing.BadSignature, signing.SignatureExpired, User.DoesNotExist):
            return None

    @staticmethod
    def validate_password_reset(password1, password2):
        if not password1 or not password2:
            return "Both fields are required."
        if password1 != password2:
            return "Passwords do not match."
        if len(password1) < 8:
            return "Password must be at least 8 characters."
        if not any(c.isupper() for c in password1):
            return "Password must contain at least one uppercase letter."
        if not any(c.isdigit() for c in password1):
            return "Password must contain at least one number."
        return None

    @staticmethod
    def reset_password(user, new_password):
        user.set_password(new_password)
        user.save()

    @staticmethod
    def get_user_by_email(email):
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None

    @staticmethod
    def verify_email_token(token):
        try:
            user_pk = signing.loads(token, salt='email-verification', max_age=3600)
            user = User.objects.get(pk=user_pk)
            user.is_active = True
            user.save()
            return user
        except (signing.BadSignature, signing.SignatureExpired, User.DoesNotExist):
            return None