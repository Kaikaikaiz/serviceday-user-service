from django.urls import path
from . import views

urlpatterns = [
    path('users/',                      views.api_user_list,         name='api-user-list'),
    path('users/me/',                   views.api_me,                name='api-me'),
    path('users/register/',             views.api_register,          name='api-register'),
    path('users/logout/',               views.api_logout,            name='api-logout'),
    path('users/forgot-password/',      views.api_forgot_password,   name='api-forgot-password'),
    path('users/reset-password/',       views.api_reset_password,    name='api-reset-password'),
    path('users/employees/emails/',     views.api_employee_emails,   name='api-employee-emails'),
]