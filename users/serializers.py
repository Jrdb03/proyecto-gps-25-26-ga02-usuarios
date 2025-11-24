from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User, PasswordResetToken


class RegisterRequestSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, validators=[validate_password])

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'user_type']
        extra_kwargs = {
            'email': {'required': True},
            'username': {'required': True},
            'password': {'required': True},
            'user_type': {'required': True}
        }

    def validate_email(self, value):
        # Validar que el email no existe
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Este email ya está registrado")
        return value

    def validate_user_type(self, value):
        # 🔄 NUEVO: Validar que el tipo de usuario es válido
        valid_types = ['user', 'artist', 'admin', 'label']
        if value not in valid_types:
            raise serializers.ValidationError("Tipo de usuario no válido")
        return value

    def create(self, validated_data):
        # Crear usuario con contraseña encriptada
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            alias=validated_data['username'],  # alias igual a username inicialmente
            user_type=validated_data['user_type']
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


class LogoutRequestSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

    def validate_refresh_token(self, value):
        """
        Validar que el refresh token tiene el formato correcto
        """
        if not value:
            raise serializers.ValidationError("El refresh token es requerido")
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        # Verificar que el email existe en el sistema
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No existe un usuario con este email")
        return value


class PasswordResetTokenSerializer(serializers.Serializer):
    token = serializers.CharField(required=True, max_length=100)

    def validate_token(self, value):
        # Verificar que el token existe y es válido
        try:
            reset_token = PasswordResetToken.objects.get(token=value)
            if not reset_token.is_valid():
                raise serializers.ValidationError("El token ha expirado o ya fue usado")
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError("Token inválido")

        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(required=True, max_length=100)
    new_password = serializers.CharField(required=True, min_length=8, validators=[validate_password])
    confirm_password = serializers.CharField(required=True, min_length=8)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Las contraseñas no coinciden"})

        # Validar token
        try:
            reset_token = PasswordResetToken.objects.get(token=attrs['token'])
            if not reset_token.is_valid():
                raise serializers.ValidationError({"token": "El token ha expirado o ya fue usado"})
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError({"token": "Token inválido"})

        attrs['reset_token'] = reset_token
        return attrs

    # Serializers para el endpoint /me
    class UserProfileSerializer(serializers.ModelSerializer):
        """Serializer para obtener el perfil del usuario (GET /me)"""
        user_type_display = serializers.CharField(source='get_user_type_display', read_only=True)

        class Meta:
            model = User
            fields = [
                'user_id',
                'email',
                'username',
                'alias',
                'avatar_url',
                'bio',
                'country',
                'user_type',
                'user_type_display',
                'preferences'
            ]
            read_only_fields = ['user_id', 'email', 'username', 'user_type']  # Estos campos no se pueden modificar

    class UserProfileUpdateSerializer(serializers.ModelSerializer):
        """Serializer para actualizar el perfil del usuario (PATCH /me)"""

        class Meta:
            model = User
            fields = ['alias', 'avatar_url', 'bio', 'country', 'preferences']

        def validate_alias(self, value):
            """Validar que el alias sea único (excepto para el usuario actual)"""
            if value:
                # Verificar si otro usuario ya tiene este alias
                user = self.instance
                if User.objects.filter(alias=value).exclude(pk=user.pk).exists():
                    raise serializers.ValidationError("Este alias ya está en uso. Por favor, elige otro.")
            return value

        def validate_preferences(self, value):
            """Validar la estructura de las preferencias"""
            if not isinstance(value, dict):
                raise serializers.ValidationError("Las preferencias deben ser un objeto JSON.")

            # Validar campos específicos de preferencias si es necesario
            allowed_preferences = ['language', 'explicit_filter']
            for key in value.keys():
                if key not in allowed_preferences:
                    raise serializers.ValidationError(f"Preferencia no permitida: {key}")

            return value