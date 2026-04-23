from asgiref.server import logger
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer, UserSerializer, RegisterSerializer
from accounts.services.account_service import AccountService
from django.conf import settings
import requests

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def api_register(request):
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    data = serializer.validated_data
    user = AccountService.register_user(
        data['username'], data['email'],
        data['first_name'], data['last_name'], data['password1'],
    )
    return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)

@api_view(['POST'])
@permission_classes([AllowAny])
def api_verify_email(request):
    """
    POST /api/v1/users/verify-email/
    Called by gateway when user clicks verification link.

    Payload: { "token": "abc123..." }
    """
    token = request.data.get('token', '')
    if not token:
        return Response(
            {'error': 'Token is required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    user = AccountService.verify_email_token(token)
    if user:
        return Response({'message': 'Email verified. You can now log in.'})

    return Response(
        {'error': 'Invalid or expired verification link.'},
        status=status.HTTP_400_BAD_REQUEST
    )


@api_view(['POST'])
@permission_classes([AllowAny])
def api_forgot_password(request):
    email = request.data.get('email', '').strip()
    if not email:
        return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

    user = AccountService.get_user_by_email(email)
    if not user:
        # Return same message whether email exists or not — prevents user enumeration
        return Response({'message': 'If that email is registered, a reset link has been sent.'})

    token = AccountService.generate_reset_token(user)

    # Build reset URL pointing to gateway
    gateway_url = getattr(settings, 'GATEWAY_URL')
    reset_url = f"{gateway_url}/reset-password/{token}/"

    # Call notification-service to send the email
    try:
        response = requests.post(
            settings.NOTIFICATION_SERVICE_URL + '/api/v1/notifications/send-reset-password/',
            json={
                'email':     email,
                'name':      user.first_name or user.username,
                'reset_url': reset_url,
            },
            timeout=5,
        )
        logger.info(f"Reset email response: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Failed to send reset email: {e}")

    # Never return the token to the gateway — link comes via email only
    return Response({'message': 'If that email is registered, a reset link has been sent.'})


@api_view(['POST'])
@permission_classes([AllowAny])
def api_reset_password(request):
    token = request.data.get('token')
    user  = AccountService.resolve_reset_token(token)
    if not user:
        return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)
    error = AccountService.validate_password_reset(
        request.data.get('password1', ''),
        request.data.get('password2', ''),
    )
    if error:
        return Response({'error': error}, status=status.HTTP_400_BAD_REQUEST)
    AccountService.reset_password(user, request.data.get('password1'))
    return Response({'message': 'Password reset successful.'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_logout(request):
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = request.data.get('refresh')
    if not refresh:
        return Response({'error': 'Refresh token required.'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        RefreshToken(refresh).blacklist()
        return Response({'message': 'Logged out successfully.'})
    except Exception:
        return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_me(request):
    return Response(UserSerializer(request.user).data)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_user_list(request):
    users = User.objects.filter(is_active=True)
    return Response(UserSerializer(users, many=True).data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_employee_emails(request):
    emails = list(
        User.objects
        .filter(is_active=True, is_staff=False)
        .values_list('email', flat=True)
    )
    return Response({'emails': emails})