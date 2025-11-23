from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import (
    RegisterRequestSerializer,
    LoginRequestSerializer,
    LogoutRequestSerializer,
    PasswordResetRequestSerializer,
    PasswordResetTokenSerializer,
    PasswordResetConfirmSerializer
)
from .models import User, PasswordResetToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.utils import timezone
from datetime import timedelta
import secrets
from django.conf import settings



@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        serializer = RegisterRequestSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            # Respuesta según el .yaml
            return Response(
                {"user_id": user.user_id},
                status=status.HTTP_201_CREATED
            )

        # Si hay errores de validación
        return Response(
            {
                "code": "VALIDATION_ERROR",
                "message": "Error de validación",
                "details": serializer.errors
            },
            status=status.HTTP_422_UNPROCESSABLE_ENTITY
        )


@api_view(['POST'])
def login_user(request):
    if request.method == 'POST':
        serializer = LoginRequestSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']

            # Generar tokens JWT
            refresh = RefreshToken.for_user(user)

            # Respuesta según el .yaml
            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh)
            }, status=status.HTTP_200_OK)

        # Manejar errores de validación
        return Response(
            {
                "code": "AUTH_ERROR",
                "message": "Error de autenticación",
                "details": serializer.errors
            },
            status=status.HTTP_422_UNPROCESSABLE_ENTITY
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    """
    Endpoint para cerrar sesión - Invalida el refresh token
    """
    if request.method == 'POST':
        serializer = LogoutRequestSerializer(data=request.data)

        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh_token']

            try:
                # Invalidar el refresh token
                token = RefreshToken(refresh_token)
                token.blacklist()

                # Respuesta exitosa
                return Response(
                    {
                        "message": "Sesión cerrada correctamente",
                        "code": "LOGOUT_SUCCESS"
                    },
                    status=status.HTTP_200_OK
                )

            except TokenError as e:
                # Token inválido o ya blacklisted
                return Response(
                    {
                        "code": "INVALID_TOKEN",
                        "message": "Token inválido o ya expirado",
                        "details": {"refresh_token": str(e)}
                    },
                    status=status.HTTP_422_UNPROCESSABLE_ENTITY
                )

            except Exception as e:
                # Error inesperado
                return Response(
                    {
                        "code": "LOGOUT_ERROR",
                        "message": "Error al cerrar sesión",
                        "details": {"error": str(e)}
                    },
                    status=status.HTTP_422_UNPROCESSABLE_ENTITY
                )

        # Errores de validación del serializer
        return Response(
            {
                "code": "VALIDATION_ERROR",
                "message": "Error de validación",
                "details": serializer.errors
            },
            status=status.HTTP_422_UNPROCESSABLE_ENTITY
        )


@api_view(['POST'])
def refresh_token(request):
    """
    Endpoint para refrescar tokens JWT
    """
    try:
        refresh_token = request.data.get('refresh_token')

        # Validar que el refresh token está presente
        if not refresh_token:
            return Response(
                {
                    "code": "VALIDATION_ERROR",
                    "message": "Refresh token es requerido",
                    "details": {"refresh_token": ["Este campo es requerido."]}
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY
            )

        # Validar y refrescar el token
        refresh = RefreshToken(refresh_token)
        new_tokens = {
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh)
        }

        return Response(new_tokens, status=status.HTTP_200_OK)

    except TokenError as e:
        # Token inválido o expirado
        return Response(
            {
                "code": "TOKEN_ERROR",
                "message": "Token inválido o expirado",
                "details": {"refresh_token": ["El token de refresh no es válido."]}
            },
            status=status.HTTP_401_UNAUTHORIZED
        )

@api_view(['POST'])
def password_reset_request(request):
    """
    Endpoint para solicitar recuperación de contraseña (GA02-179)
    Con límite simple de 3 intentos por token
    """
    if request.method == 'POST':
        serializer = PasswordResetRequestSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                user = User.objects.get(email=email)

                # Buscar token existente no expirado
                existing_token = PasswordResetToken.objects.filter(
                    user=user,
                    is_used=False,
                    expires_at__gt=timezone.now()
                ).first()

                # Si existe un token y ya tiene 3 o más solicitudes, bloquear
                if existing_token and existing_token.request_count >= 3:
                    return Response({
                        "code": "TOO_MANY_ATTEMPTS",
                        "message": "Demasiados intentos. Solicita un nuevo enlace."
                    }, status=status.HTTP_400_BAD_REQUEST)

                # Generar token único
                token = secrets.token_urlsafe(32)

                # Crear o actualizar token de recuperación
                if existing_token:
                    # Usar token existente e incrementar contador
                    existing_token.token = token
                    existing_token.request_count += 1
                    existing_token.save()
                    reset_token = existing_token
                else:
                    # Crear nuevo token
                    reset_token = PasswordResetToken.objects.create(
                        user=user,
                        token=token,
                        expires_at=timezone.now() + timedelta(hours=24),
                        request_count=1
                    )

                # En desarrollo, retornamos el link para facilitar pruebas
                reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"

                if settings.DEBUG:
                    return Response({
                        "message": "Solicitud de recuperación procesada",
                        "reset_link": reset_link,
                        "attempts": reset_token.request_count,  # Para ver el contador
                        "code": "RESET_REQUEST_SUCCESS"
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        "message": "Si el email existe en nuestro sistema, recibirás un enlace de recuperación",
                        "code": "RESET_REQUEST_SUCCESS"
                    }, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({
                    "message": "Si el email existe en nuestro sistema, recibirás un enlace de recuperación",
                    "code": "RESET_REQUEST_SUCCESS"
                }, status=status.HTTP_200_OK)

        return Response({
            "code": "VALIDATION_ERROR",
            "message": "Error de validación",
            "details": serializer.errors
        }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


@api_view(['POST'])
def password_reset_validate_token(request):
    """
    Endpoint para validar token de recuperación (GA02-176)
    """
    if request.method == 'POST':
        serializer = PasswordResetTokenSerializer(data=request.data)

        if serializer.is_valid():
            token = serializer.validated_data['token']

            try:
                reset_token = PasswordResetToken.objects.get(token=token)

                if reset_token.is_valid():
                    return Response({
                        "message": "Token válido",
                        "code": "TOKEN_VALID",
                        "email": reset_token.user.email  # Opcional: para mostrar en el frontend
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        "code": "INVALID_TOKEN",
                        "message": "Token inválido o expirado"
                    }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            except PasswordResetToken.DoesNotExist:
                return Response({
                    "code": "INVALID_TOKEN",
                    "message": "Token inválido"
                }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        return Response({
            "code": "VALIDATION_ERROR",
            "message": "Error de validación",
            "details": serializer.errors
        }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


@api_view(['POST'])
def password_reset_confirm(request):
    """
    Endpoint para establecer nueva contraseña (GA02-175)
    """
    if request.method == 'POST':
        serializer = PasswordResetConfirmSerializer(data=request.data)

        if serializer.is_valid():
            reset_token = serializer.validated_data['reset_token']
            new_password = serializer.validated_data['new_password']

            # Actualizar contraseña del usuario
            user = reset_token.user
            user.set_password(new_password)
            user.save()

            # Marcar token como usado
            reset_token.is_used = True
            reset_token.save()

            return Response({
                "message": "Contraseña actualizada correctamente",
                "code": "PASSWORD_RESET_SUCCESS"
            }, status=status.HTTP_200_OK)

        return Response({
            "code": "VALIDATION_ERROR",
            "message": "Error de validación",
            "details": serializer.errors
        }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)