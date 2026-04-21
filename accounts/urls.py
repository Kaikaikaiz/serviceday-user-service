from django.urls import path
from . import views

urlpatterns = [
    # ── Template views ────────────────────────────────
    path('login/',                      views.user_login,      name='login'),
    path('logout/',                     views.user_logout,     name='logout'),
    path('register/',                   views.user_register,   name='register'),
    path('forgot-password/',            views.forgot_password, name='forgot-password'),
    path('reset-password/<str:token>/', views.reset_password,  name='reset-password'),

    # ── API views (called by other microservices) ─────
    path('users/',                      views.api_user_list,       name='api-user-list'),
    path('users/me/',                   views.api_me,              name='api-me'),
    path('users/register/',             views.api_register,        name='api-register'),
    path('users/employees/emails/',     views.api_employee_emails, name='api-employee-emails'),
]