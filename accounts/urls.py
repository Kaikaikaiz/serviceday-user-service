from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    path('register/',                   views.RegisterView.as_view(),       name='register'),
    path('login/',                      views.LoginView.as_view(),          name='login'),
    path('logout/',                     views.LogoutView.as_view(),         name='logout'),
    path('profile/',                    views.UserProfileView.as_view(),    name='profile'),
    path('forgot-password/',            views.ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/',             views.ResetPasswordView.as_view(),  name='reset-password'),
    path('token/refresh/',              TokenRefreshView.as_view(),         name='token-refresh'),
    path('<int:pk>/',                   views.UserDetailView.as_view(),     name='user-detail'),
]