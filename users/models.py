from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    # Añadir related_name único para evitar conflictos
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name='custom_user_set',
        related_query_name='user',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='custom_user_set',
        related_query_name='user',
    )

    # Tus campos personalizados
    user_id = models.CharField(max_length=50, unique=True, blank=True)
    alias = models.CharField(max_length=50, unique=True, blank=True, null=True)
    avatar_url = models.URLField(blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    preferences = models.JSONField(default=dict, blank=True)

    def save(self, *args, **kwargs):
        if not self.user_id:
            import uuid
            self.user_id = f"u_{uuid.uuid4().hex[:8]}"
        if not self.alias:
            self.alias = self.username
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.alias} ({self.email})"


class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    request_count = models.IntegerField(default=1)

    def is_valid(self):
        from django.utils import timezone
        return not self.is_used and timezone.now() < self.expires_at

    def __str__(self):
        return f"Token for {self.user.email} - Valid: {self.is_valid()}"