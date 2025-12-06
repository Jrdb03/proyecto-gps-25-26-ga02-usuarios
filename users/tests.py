from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken


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


class UserLogoutTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.logout_url = reverse('logout')

        # Crear usuario y tokens
        self.user = User.objects.create_user(
            username='logoutuser',
            email='logout@example.com',
            password='SecurePass123!'
        )

        # Generar tokens válidos
        refresh = RefreshToken.for_user(self.user)
        self.valid_refresh_token = str(refresh)
        self.valid_access_token = str(refresh.access_token)

        # Token inválido para pruebas
        self.invalid_refresh_token = 'invalid.token.here'

    def test_successful_logout(self):
        """Test: Logout exitoso debe retornar 200 y mensaje de éxito"""
        # Autenticar al usuario primero
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.valid_access_token}')

        payload = {
            'refresh_token': self.valid_refresh_token
        }

        response = self.client.post(
            self.logout_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['code'], 'LOGOUT_SUCCESS')
        self.assertEqual(response.data['message'], 'Sesión cerrada correctamente')

    def test_logout_invalid_token(self):
        """Test: Logout con token inválido debe retornar error 422"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.valid_access_token}')

        payload = {
            'refresh_token': self.invalid_refresh_token
        }

        response = self.client.post(
            self.logout_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertEqual(response.data['code'], 'INVALID_TOKEN')

    def test_logout_missing_refresh_token(self):
        """Test: Logout sin refresh_token debe retornar error 422"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.valid_access_token}')

        payload = {
            # Falta refresh_token
        }

        response = self.client.post(
            self.logout_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertEqual(response.data['code'], 'VALIDATION_ERROR')
        self.assertIn('refresh_token', response.data['details'])

    def test_logout_without_authentication(self):
        """Test: Logout sin autenticación debe retornar error 401"""
        # No establecer credenciales de autenticación

        payload = {
            'refresh_token': self.valid_refresh_token
        }

        response = self.client.post(
            self.logout_url,
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_double_logout_same_token(self):
        """Test: Logout dos veces con el mismo token debe fallar la segunda vez"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.valid_access_token}')

        payload = {
            'refresh_token': self.valid_refresh_token
        }

        # Primer logout exitoso
        response1 = self.client.post(
            self.logout_url,
            payload,
            format='json'
        )
        self.assertEqual(response1.status_code, status.HTTP_200_OK)

        # Segundo logout debe fallar
        response2 = self.client.post(
            self.logout_url,
            payload,
            format='json'
        )
        self.assertEqual(response2.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertEqual(response2.data['code'], 'INVALID_TOKEN')


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


# Pruebas para el endpoint /me
class UserProfileTests(TestCase):
    """
    Pruebas para el endpoint /me (perfil de usuario)
    """

    def setUp(self):
        self.client = APIClient()
        self.profile_url = reverse('user-profile')

        # Crear usuarios de prueba
        self.user = User.objects.create_user(
            username='testuser_profile',
            email='testprofile@example.com',
            password='testpass123',
            alias='testalias',
            bio='Biografía de prueba',
            country='España',
            user_type='artist'  # Tipo de usuario artista
        )

        # Otro usuario para pruebas de alias único
        self.other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='testpass123',
            alias='aliasunico',
            user_type='user'
        )

        # Obtener tokens para autenticación
        login_response = self.client.post(reverse('login'), {
            'email': 'testprofile@example.com',
            'password': 'testpass123'
        })
        self.access_token = login_response.data['access_token']

        # Configurar cliente autenticado
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')

    def test_get_profile_authenticated(self):
        """Test 1: Usuario autenticado puede obtener su perfil"""
        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'testprofile@example.com')
        self.assertEqual(response.data['alias'], 'testalias')
        self.assertEqual(response.data['bio'], 'Biografía de prueba')
        self.assertEqual(response.data['country'], 'España')
        self.assertEqual(response.data['user_type'], 'artist')  # Verificar tipo
        self.assertEqual(response.data['user_type_display'], 'Artista')  # Display name

    def test_get_profile_unauthenticated(self):
        """Test 2: Usuario no autenticado no puede obtener perfil"""
        client = APIClient()  # Cliente sin autenticar
        response = client.get(self.profile_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_profile_authenticated(self):
        """Test 3: Usuario autenticado puede actualizar su perfil"""
        update_data = {
            'alias': 'nuevoalias',
            'bio': 'Nueva biografía',
            'country': 'Francia',
            'preferences': {
                'language': 'en',
                'explicit_filter': True
            }
        }

        response = self.client.patch(
            self.profile_url,
            update_data,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['alias'], 'nuevoalias')
        self.assertEqual(response.data['bio'], 'Nueva biografía')
        self.assertEqual(response.data['country'], 'Francia')
        self.assertEqual(response.data['preferences']['language'], 'en')

        # Verificar que se actualizó en la base de datos
        self.user.refresh_from_db()
        self.assertEqual(self.user.alias, 'nuevoalias')
        self.assertEqual(self.user.preferences['language'], 'en')

    def test_update_profile_duplicate_alias(self):
        """Test 4: No se puede usar un alias ya existente"""
        update_data = {
            'alias': 'aliasunico'  # Alias que ya usa other_user
        }

        response = self.client.patch(
            self.profile_url,
            update_data,
            format='json'
        )

        # VERIFICACIÓN ACTUALIZADA
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('alias', response.data['details'])

        # El mensaje exacto puede variar, pero el código de error debe ser 'unique'
        alias_error = response.data['details']['alias'][0]
        self.assertEqual(alias_error.code, 'unique')

    def test_update_profile_partial(self):
        """Test 5: Se puede actualizar solo algunos campos"""
        update_data = {
            'bio': 'Solo actualizo la biografía'
        }

        response = self.client.patch(
            self.profile_url,
            update_data,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['bio'], 'Solo actualizo la biografía')
        # Los demás campos deben mantenerse igual
        self.assertEqual(response.data['alias'], 'testalias')
        self.assertEqual(response.data['country'], 'España')
        self.assertEqual(response.data['user_type'], 'artist')  # Tipo no cambia

    def test_update_profile_invalid_preferences(self):
        """Test 6: Preferencias inválidas retornan error"""
        update_data = {
            'preferences': 'esto_no_es_un_objeto'  # Preferencias inválidas
        }

        response = self.client.patch(
            self.profile_url,
            update_data,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('preferences', response.data['details'])

    def test_user_type_is_read_only(self):
        """Test 7: El tipo de usuario no se puede modificar después del registro"""
        update_data = {
            'user_type': 'admin'  # Intentar cambiar tipo de usuario
        }

        response = self.client.patch(
            self.profile_url,
            update_data,
            format='json'
        )

        # Debería ignorar el campo user_type (no está en el serializer de update)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user_type'], 'artist')  # No debería cambiar