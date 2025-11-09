from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User


class RegisterRequestSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, validators=[validate_password])

    class Meta:
        model = User
        fields = ['email', 'password', 'username']
        extra_kwargs = {
            'email': {'required': True},
            'username': {'required': True},
            'password': {'required': True},
        }

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


class LoginRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        # Validar que ambos campos estén presentes
        if email and password:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError({
                    'email': 'Login incorrecto, no existe un usuario con este email.'
                })

            # Verificar la contraseña
            if not user.check_password(password):
                raise serializers.ValidationError({
                    'password': 'Login incorrecto, la contraseña es incorrecta.'
                })

            # Verificar que el usuario esté activo
            if not user.is_active:
                raise serializers.ValidationError({
                    'email': 'Login incorrecto, esta cuenta está desactivada.'
                })

            # Si es correcto, añadir el usuario a los atributos validados
            attrs['user'] = user

        return attrs