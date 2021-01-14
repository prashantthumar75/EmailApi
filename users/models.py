from django.db import models

from django.contrib.auth.models import AbstractUser, BaseUserManager

USER_TYPE_CHOICES = (
    ('organization', 'organization'),
    ('department', 'department'),
    ('teacher', 'teacher'),
    ('student', 'student'),
)

class User(AbstractUser):

    user_type = models.CharField(
        max_length=32, choices=USER_TYPE_CHOICES, default='student')

    def __str__(self):
        return f"{self.username}"







## added by Prashant Thummar

import re
import hashlib
import datetime

from django.conf import settings
from django.db import models, transaction
from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from django.contrib.auth.tokens import default_token_generator


token_generator = default_token_generator

SHA1_RE = re.compile('^[a-f0-9]{40}$')

from django.conf import settings

from django.utils.module_loading import import_string

TokenModel = import_string(getattr(settings, 'REST_AUTH_TOKEN_MODEL', 'rest_framework.authtoken.models.Token'))

# class User created by rajesh


