from rest_framework import serializers
from django.contrib.auth.models import User, Group
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['groups']   = list(user.groups.values_list('name', flat=True))
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data             = super().validate(attrs)
        data['groups']   = list(self.user.groups.values_list('name', flat=True))
        data['username'] = self.user.username
        data['role']     = 'admin' if self.user.is_staff else 'employee'
        return data

class UserSerializer(serializers.ModelSerializer):
    """Read-only serializer for user data."""
    role = serializers.SerializerMethodField()

    class Meta:
        model  = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role']

    def get_role(self, obj):
        if obj.groups.filter(name='Administrator').exists() or obj.is_staff:
            return 'admin'
        return 'employee'


class RegisterSerializer(serializers.Serializer):
    """Topic 7.4a — Input validation for registration."""
    username   = serializers.CharField(max_length=150)
    email      = serializers.EmailField()
    first_name = serializers.CharField(max_length=100)
    last_name  = serializers.CharField(max_length=100)
    password1  = serializers.CharField(min_length=8, write_only=True)
    password2  = serializers.CharField(min_length=8, write_only=True)

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already taken.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already registered.")
        return value

    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError({"password2": "Passwords do not match."})
        if not any(c.isupper() for c in data['password1']):
            raise serializers.ValidationError({"password1": "Password must contain at least one uppercase letter."})
        if not any(c.isdigit() for c in data['password1']):
            raise serializers.ValidationError({"password1": "Password must contain at least one number."})
        return data


class EmployeeEmailListSerializer(serializers.Serializer):
    """Returns list of employee emails for notification-service."""
    emails = serializers.ListField(child=serializers.EmailField())