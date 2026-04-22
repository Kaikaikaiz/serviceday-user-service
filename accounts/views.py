from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from .serializers import UserSerializer, RegisterSerializer
from accounts.services.account_service import AccountService


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
def api_forgot_password(request):
    email = request.data.get('email', '').strip()
    if not email:
        return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)
    user  = AccountService.get_user_by_email(email)
    if not user:
        return Response({'message': 'If that email is registered, a reset link has been sent.'})
    token = AccountService.generate_reset_token(user)
    return Response({'message': 'Password reset token generated.', 'token': token})


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
@permission_classes([IsAdminUser])
def api_employee_emails(request):
    emails = list(
        User.objects
        .filter(is_active=True, is_staff=False)
        .values_list('email', flat=True)
    )
    return Response({'emails': emails})