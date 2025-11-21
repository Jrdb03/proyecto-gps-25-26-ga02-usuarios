"""
URL configuration for backend_usuarios project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from users import views  # Importamos las vistas de la app users

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/auth/register', views.register_user, name='register'),
    # Aquí añadiremos más endpoints después
    path('api/v1/auth/login', views.login_user, name='login'),
    path('api/v1/auth/logout', views.logout_user, name='logout'),
    path('api/v1/auth/password-reset/request', views.password_reset_request, name='password-reset-request'),
    path('api/v1/auth/password-reset/validate-token', views.password_reset_validate_token, name='password-reset-validate'),
    path('api/v1/auth/password-reset/confirm', views.password_reset_confirm, name='password-reset-confirm'),
]
