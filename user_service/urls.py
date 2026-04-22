from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('admin/', admin.site.urls),

    # ── JWT Auth ──────────────────────────────────────
    path('api/v1/auth/token/refresh/', TokenRefreshView.as_view(),    name='token_refresh'),

    # ── User API ──────────────────────────────────────
    path('api/v1/', include('accounts.urls')),
]