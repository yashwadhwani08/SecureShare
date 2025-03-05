from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    ROLES = (
        ('SUPERADMIN', 'SuperAdmin'),
        ('USER', 'User'),
        ('GUEST', 'Guest'),
    )
    role = models.CharField(max_length=20, choices=ROLES, default='USER')
    mfa_secret = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.username
