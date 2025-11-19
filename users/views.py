from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import RegisterRequestSerializer, LoginRequestSerializer, LogoutRequestSerializer

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError


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