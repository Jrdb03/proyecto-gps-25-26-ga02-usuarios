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
def password_reset_request(request):
    """
    Endpoint para solicitar recuperación de contraseña (GA02-179)
    """
    if request.method == 'POST':
        serializer = PasswordResetRequestSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                user = User.objects.get(email=email)

                # Generar token único
                token = secrets.token_urlsafe(32)

                # Crear o actualizar token de recuperación
                reset_token, created = PasswordResetToken.objects.update_or_create(
                    user=user,
                    defaults={
                        'token': token,
                        'expires_at': timezone.now() + timedelta(hours=24),
                        'is_used': False
                    }
                )

                # En desarrollo, retornamos el link para facilitar pruebas
                reset_link = f"http://localhost:5173/reset-password?token={token}"

                if settings.DEBUG:
                    return Response({
                        "message": "Solicitud de recuperación procesada",
                        "reset_link": reset_link,
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