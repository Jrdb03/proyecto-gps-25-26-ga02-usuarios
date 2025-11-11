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


class UserLoginTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('login')
        # Crear un usuario de prueba
        self.user = User.objects.create_user(
            username='testuser242',
            email='test242@example.com',
            password='SecurePass242!'
        )

    def test_successful_login(self):
        """Test: Login exitoso debe retornar tokens"""
        payload = {
            'email': 'test242@example.com',
            'password': 'SecurePass242!'
        }

        response = self.client.post(
            self.login_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        # Verificar que los tokens son strings no vacíos
        self.assertTrue(len(response.data['access_token']) > 0)
        self.assertTrue(len(response.data['refresh_token']) > 0)

    def test_login_nonexistent_user(self):
        """Test: Usuario inexistente debe retornar error 422"""
        payload = {
            'email': 'nonexistent@example.com',
            'password': 'anypassword'
        }

        response = self.client.post(
            self.login_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertEqual(response.data['code'], 'AUTH_ERROR')
        self.assertIn('email', response.data['details'])

    def test_login_wrong_password(self):
        """Test: Contraseña incorrecta debe retornar error 422"""
        payload = {
            'email': 'test242@example.com',
            'password': 'WrongPassword123!'
        }

        response = self.client.post(
            self.login_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertEqual(response.data['code'], 'AUTH_ERROR')
        self.assertIn('password', response.data['details'])

    def test_login_missing_email(self):
        """Test: Falta email debe retornar error 422"""
        payload = {
            'password': 'SecurePass123!'
        }

        response = self.client.post(
            self.login_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('email', response.data['details'])

    def test_login_missing_password(self):
        """Test: Falta password debe retornar error 422"""
        payload = {
            'email': 'test242@example.com'
        }

        response = self.client.post(
            self.login_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('password', response.data['details'])

    def test_login_inactive_user(self):
        """Test: Usuario inactivo debe retornar error"""
        # Crear usuario inactivo
        inactive_user = User.objects.create_user(
            username='inactive',
            email='inactive@example.com',
            password='SecurePass123!',
            is_active=False
        )

        payload = {
            'email': 'inactive@example.com',
            'password': 'SecurePass123!'
        }

        response = self.client.post(
            self.login_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('email', response.data['details'])


# Pruebas para Refresh Token
class TokenRefreshTests(TestCase):
    """
    Pruebas para el endpoint de refresh token
    """

    def setUp(self):
        self.client = APIClient()
        self.refresh_url = reverse('refresh-token')

        # Crear usuario de prueba
        self.user = User.objects.create_user(
            username='testuser_refresh',
            email='testrefresh@example.com',
            password='testpass123'
        )

    def test_successful_token_refresh(self):
        """PASO 2.1: Test que refresh exitoso retorna nuevos tokens"""
        # Primero hacer login para obtener tokens válidos
        login_response = self.client.post(reverse('login'), {
            'email': 'testrefresh@example.com',
            'password': 'testpass123'
        })
        refresh_token = login_response.data['refresh_token']

        # Luego hacer refresh con el token obtenido
        response = self.client.post(
            self.refresh_url,
            {'refresh_token': refresh_token},
            format='json'
        )

        # Verificar respuesta exitosa
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)

        # Verificaciones
        # 1. Los tokens tienen longitud razonable
        self.assertTrue(len(response.data['access_token']) > 50)
        self.assertTrue(len(response.data['refresh_token']) > 50)

        # 2. Los tokens son strings no vacíos
        self.assertIsInstance(response.data['access_token'], str)
        self.assertIsInstance(response.data['refresh_token'], str)

        # 3. Podemos verificar el formato JWT (opcional)
        access_token = response.data['access_token']
        self.assertTrue(access_token.count('.') == 2)  # Los JWT tienen 2 puntos

    def test_refresh_missing_token(self):
        """PASO 2.2: Test que falta refresh token retorna error 422"""
        response = self.client.post(
            self.refresh_url,
            {},  # Body vacío - falta refresh_token
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('refresh_token', response.data['details'])

    def test_refresh_invalid_token(self):
        """PASO 2.3: Test que token inválido retorna error 401"""
        response = self.client.post(
            self.refresh_url,
            {'refresh_token': 'token.invalido.malformado'},
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['code'], 'TOKEN_ERROR')