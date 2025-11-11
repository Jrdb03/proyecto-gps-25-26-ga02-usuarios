from django.shortcuts import render

# Create your views here.
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import RegisterRequestSerializer, LoginRequestSerializer

from rest_framework_simplejwt.tokens import RefreshToken


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