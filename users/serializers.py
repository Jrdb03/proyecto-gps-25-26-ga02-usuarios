from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User


class RegisterRequestSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, validators=[validate_password])

    class Meta:
        model = User
        fields = ['email', 'password', 'username']  # username será el alias inicial

    def validate_email(self, value):
        # Validar que el email no existe
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Este email ya está registrado")
        return value

    def create(self, validated_data):
        # Crear usuario con contraseña encriptada
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            alias=validated_data['username']  # alias igual a username inicialmente
        )
        return user