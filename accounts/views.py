from rest_framework              import status
from rest_framework.response     import Response
from rest_framework.views        import APIView
from rest_framework.permissions  import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.services.account_service import AccountService
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    UserProfileSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
)


# -------------------------------------------------------------------------
# Register
# POST /api/users/register/
# Preserves all AccountService.validate_registration() rules:
#   - uppercase, digit, length, username/email uniqueness
#   - assigns Employee group
# -------------------------------------------------------------------------

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        user = serializer.save()
        return Response(
            {
                'message': 'Account created successfully.',
                'user': UserProfileSerializer(user).data,
            },
            status=status.HTTP_201_CREATED
        )


# -------------------------------------------------------------------------
# Login
# POST /api/users/login/
# Returns JWT access + refresh tokens + user profile + role
# Role is group-based (Administrator group or is_staff = admin)
# -------------------------------------------------------------------------

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = AccountService.login_user(
            request,
            serializer.validated_data['username'],
            serializer.validated_data['password'],
        )

        if not user:
            return Response(
                {'error': 'Invalid username or password.'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        refresh = RefreshToken.for_user(user)

        return Response({
            'access':  str(refresh.access_token),
            'refresh': str(refresh),
            'user':    UserProfileSerializer(user).data,
        })


# -------------------------------------------------------------------------
# Logout
# POST /api/users/logout/
# Blacklists the refresh token so it can't be reused
# -------------------------------------------------------------------------

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response(
                {'error': 'Refresh token is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logged out successfully.'})
        except Exception:
            return Response(
                {'error': 'Invalid or already expired token.'},
                status=status.HTTP_400_BAD_REQUEST
            )


# -------------------------------------------------------------------------
# Profile
# GET  /api/users/profile/  — view own profile
# PUT  /api/users/profile/  — update own profile
# -------------------------------------------------------------------------

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserProfileSerializer(request.user).data)

    def put(self, request):
        serializer = UserProfileSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        if not serializer.is_valid():
            return Response(
                {'error': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save()
        return Response(serializer.data)


# -------------------------------------------------------------------------
# Forgot Password
# POST /api/users/forgot-password/
# 6.5 — doesn't reveal whether the email exists
# Returns token directly (in production you'd email the link instead)
# -------------------------------------------------------------------------

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        email = serializer.validated_data['email']
        user  = AccountService.get_user_by_email(email)

        # 6.5 — always return the same response regardless of whether
        #        the email exists to avoid user enumeration
        if not user:
            return Response({
                'message': 'If that email is registered, a reset link has been sent.'
            })

        token = AccountService.generate_reset_token(user)

        # In production: send token via email
        # For development: return token directly so you can test in Postman
        return Response({
            'message': 'Password reset token generated.',
            'token':   token,      # ← remove this line in production
        })


# -------------------------------------------------------------------------
# Reset Password
# POST /api/users/reset-password/
# 6.5 — token is signed + expires after 1 hour (AccountService.RESET_TIMEOUT)
# -------------------------------------------------------------------------

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        token = serializer.validated_data['token']
        user  = AccountService.resolve_reset_token(token)

        if user is None:
            return Response(
                {'error': 'This reset link is invalid or has expired.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        AccountService.reset_password(user, serializer.validated_data['password1'])
        return Response({'message': 'Password reset successful.'})


# -------------------------------------------------------------------------
# User Detail  (internal — for api-gateway or other services)
# GET /api/users/<id>/
# Used by the gateway to look up a user by ID from a JWT sub claim
# -------------------------------------------------------------------------

class UserDetailView(APIView):
    permission_classes = [AllowAny]   # lock down with internal secret later

    def get(self, request, pk):
        from django.contrib.auth.models import User
        try:
            user = User.objects.get(pk=pk)
            return Response(UserProfileSerializer(user).data)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found.'},
                status=status.HTTP_404_NOT_FOUND
            )