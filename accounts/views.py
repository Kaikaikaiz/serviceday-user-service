"""
User Service — views.py
Contains both:
- Template views (login, logout, register, password reset)
- API views (for other microservices to call)
"""

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.utils import timezone

from accounts.services.account_service import AccountService

# ── REST API imports ──────────────────────────────────────────
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from .serializers import UserSerializer, RegisterSerializer


# ─────────────────────────────────────────────────────────────
# Template Views (Topic 9.1 — Session handling)
# ─────────────────────────────────────────────────────────────

def user_login(request):
    if request.user.is_authenticated:
        if request.user.groups.filter(name="Administrator").exists():
            return redirect('ngo:admin_dashboard')
        return redirect('ngo:ngo-list')

    next_url = request.GET.get('next', '')

    if request.method == "POST":
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        next_url = request.POST.get('next', '')

        user = AccountService.login_user(request, username, password)

        if user:
            # Topic 7.2b — rotate session ID on login
            request.session.cycle_key()

            is_admin = user.groups.filter(name="Administrator").exists() or user.is_staff

            # Topic 9.1a — store admin session metadata
            if is_admin:
                request.session['role']       = 'admin'
                request.session['login_time'] = timezone.now().isoformat()
                request.session['username']   = user.username
            # Topic 9.1b — store employee session metadata
            else:
                request.session['role']       = 'employee'
                request.session['login_time'] = timezone.now().isoformat()
                request.session['username']   = user.username

            if next_url:
                return redirect(next_url)
            if is_admin:
                return redirect('ngo:admin_dashboard')
            return redirect('ngo:ngo-list')

        messages.error(request, "Invalid username or password.")

    return render(request, "accounts/login.html", {'next': next_url})


@require_POST
@login_required
def user_logout(request):
    request.session.flush()
    AccountService.logout_user(request)
    return redirect('login')


def user_register(request):
    if request.user.is_authenticated:
        return redirect('ngo:ngo-list')

    if request.method == "POST":
        username   = request.POST.get('username', '').strip()
        email      = request.POST.get('email', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        last_name  = request.POST.get('last_name', '').strip()
        password1  = request.POST.get('password1', '')
        password2  = request.POST.get('password2', '')

        error = AccountService.validate_registration(username, email, password1, password2)
        if error:
            messages.error(request, error)
        else:
            AccountService.register_user(username, email, first_name, last_name, password1)
            messages.success(request, "Account created! Please log in.")
            return redirect('login')

    return render(request, "accounts/register.html")


def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get('email', '').strip()
        if not email:
            messages.error(request, "Please enter your email address.")
        else:
            user = AccountService.get_user_by_email(email)
            if user:
                token = AccountService.generate_reset_token(user)
                return redirect('reset-password', token=token)
            messages.info(request, "If that email is registered, a reset link has been sent.")

    return render(request, "accounts/forgot_password.html")


def reset_password(request, token):
    user = AccountService.resolve_reset_token(token)

    if user is None:
        messages.error(request, "This reset link is invalid or has expired.")
        return redirect('forgot-password')

    if request.method == "POST":
        error = AccountService.validate_password_reset(
            request.POST.get('password1', ''),
            request.POST.get('password2', ''),
        )
        if error:
            messages.error(request, error)
        else:
            AccountService.reset_password(user, request.POST.get('password1'))
            messages.success(request, "Password reset successful. Please log in.")
            return redirect('login')

    return render(request, "accounts/reset_password.html", {'reset_user': user})


# ─────────────────────────────────────────────────────────────
# API Views — called by other microservices
# ─────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([AllowAny])
def api_register(request):
    """
    POST /api/v1/users/register/
    Register a new employee account.
    Topic 7.4a — input validation via serializer.
    """
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    user = AccountService.register_user(
        data['username'],
        data['email'],
        data['first_name'],
        data['last_name'],
        data['password1'],
    )
    return Response(
        UserSerializer(user).data,
        status=status.HTTP_201_CREATED
    )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_me(request):
    """
    GET /api/v1/users/me/
    Returns current logged-in user info.
    Used by gateway to display user profile.
    """
    return Response(UserSerializer(request.user).data)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_employee_emails(request):
    """
    GET /api/v1/users/employees/emails/
    Returns all employee emails.
    Called by notification-service to get broadcast recipients.
    """
    emails = list(
        User.objects
        .filter(is_active=True, is_staff=False)
        .values_list('email', flat=True)
    )
    return Response({'emails': emails})


@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_user_list(request):
    """
    GET /api/v1/users/
    Returns all users. Admin only.
    """
    users      = User.objects.filter(is_active=True)
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)