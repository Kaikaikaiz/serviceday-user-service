from django.contrib.auth.models import User
from rest_framework import serializers
from accounts.services.account_service import AccountService


class RegisterSerializer(serializers.Serializer):
    username   = serializers.CharField(max_length=150)
    email      = serializers.EmailField()
    first_name = serializers.CharField(max_length=150)
    last_name  = serializers.CharField(max_length=150)
    password1  = serializers.CharField(write_only=True)
    password2  = serializers.CharField(write_only=True)

    def validate(self, data):
        error = AccountService.validate_registration(
            data['username'],
            data['email'],
            data['password1'],
            data['password2'],
        )
        if error:
            raise serializers.ValidationError(error)
        return data

    def create(self, validated_data):
        return AccountService.register_user(
            username   = validated_data['username'],
            email      = validated_data['email'],
            first_name = validated_data['first_name'],
            last_name  = validated_data['last_name'],
            password   = validated_data['password1'],
        )


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


class UserProfileSerializer(serializers.ModelSerializer):
    role = serializers.SerializerMethodField()

    class Meta:
        model  = User
        fields = [
            'id', 'username', 'email',
            'first_name', 'last_name',
            'is_active', 'date_joined', 'role'
        ]
        read_only_fields = ['id', 'date_joined']

    def get_role(self, obj):
        if obj.groups.filter(name="Administrator").exists() or obj.is_staff:
            return "admin"
        return "employee"


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetPasswordSerializer(serializers.Serializer):
    token     = serializers.CharField()
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        error = AccountService.validate_password_reset(
            data['password1'],
            data['password2'],
        )
        if error:
            raise serializers.ValidationError(error)
        return data