from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from .models import User


class UserRegistrationTests(TestCase):
    def setUp(self):
        """Configuración inicial para cada test"""
        self.client = APIClient()
        self.register_url = reverse('register')
        self.valid_payload = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'SecurePass123!'  # Contraseña más segura
        }

    def test_successful_registration(self):
        """Test: Registro exitoso debe retornar 201 y user_id"""
        response = self.client.post(
            self.register_url,
            self.valid_payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('user_id', response.data)
        self.assertTrue(User.objects.filter(email='test@example.com').exists())

    def test_registration_duplicate_email(self):
        """Test: Email duplicado debe retornar error 422"""
        # Crear usuario primero
        User.objects.create_user(
            username='existinguser',
            email='test@example.com',
            password='AnotherSecurePass123!'
        )

        # Intentar crear otro con mismo email
        response = self.client.post(
            self.register_url,
            self.valid_payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertEqual(response.data['code'], 'VALIDATION_ERROR')
        self.assertIn('email', response.data['details'])

    def test_registration_short_password(self):
        """Test: Contraseña muy corta debe retornar error 422"""
        payload = {
            'username': 'testuser2',
            'email': 'test2@example.com',
            'password': '123'  # Contraseña muy corta
        }

        response = self.client.post(
            self.register_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('password', response.data['details'])

    def test_registration_missing_email(self):
        """Test: Falta email debe retornar error 422"""
        payload = {
            'username': 'testuser3',
            'password': 'SecurePass123!'  # Contraseña segura para evitar otros errores
            # Falta email
        }

        response = self.client.post(
            self.register_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('email', response.data['details'])

    def test_registration_missing_password(self):
        """Test: Falta password debe retornar error 422"""
        payload = {
            'username': 'testuser4',
            'email': 'test4@example.com'
            # Falta password
        }

        response = self.client.post(
            self.register_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('password', response.data['details'])

    def test_registration_common_password(self):
        """Test: Contraseña común debe retornar error 422"""
        payload = {
            'username': 'testuser5',
            'email': 'test5@example.com',
            'password': 'password'  # Contraseña muy común
        }

        response = self.client.post(
            self.register_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('password', response.data['details'])

    def test_user_id_generated_automatically(self):
        """Test: user_id debe generarse automáticamente"""
        response = self.client.post(
            self.register_url,
            self.valid_payload,
            format='json'
        )

        user = User.objects.get(email='test@example.com')
        self.assertTrue(user.user_id.startswith('u_'))
        self.assertEqual(len(user.user_id), 10)  # u_ + 8 caracteres