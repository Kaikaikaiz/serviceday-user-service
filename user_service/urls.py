from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)

urlpatterns = [
    path('admin/', admin.site.urls),

    # ── JWT Auth ──────────────────────────────────────
    path('api/v1/auth/token/refresh/', TokenRefreshView.as_view(),    name='token_refresh'),

    # ── User API ──────────────────────────────────────
    path('api/v1/', include('accounts.urls')),

    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),

    # Swagger UI — interactive docs
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

    # ReDoc — cleaner read-only docs
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]