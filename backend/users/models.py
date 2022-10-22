from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.core.mail import send_mail
from django.utils import timezone
from uuid import uuid4


class UserManager(BaseUserManager):
    def _create_user(
        self, email, password, is_staff, is_superuser, is_verified, **kwargs
    ):
        """
        Creates and Saves a User with a given email and password.
        """
        now = timezone.now()
        if not email:
            raise ValueError("Email not provided")
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            is_staff=is_staff,
            is_superuser=is_superuser,
            is_verified=is_verified,
            last_login=now,
            date_joined=now,
            **kwargs
        )
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_user(self, email, password, **kwargs):
        return self._create_user(email, password, False, False, False, **kwargs)

    def create_superuser(self, email, password, **kwargs):
        return self._create_user(email, password, True, True, True, **kwargs)


class User(AbstractBaseUser, PermissionsMixin):
    """
    User model with email as USERFIELD_NAME instead of username.

    Email and password are required.
    """

    id: str = models.UUIDField(default=uuid4, primary_key=True)

    first_name: str = models.CharField(max_length=30, blank=True)
    last_name: str = models.CharField(max_length=30, blank=True)
    email: str = models.EmailField(max_length=100, blank=False, unique=True)
    is_staff: bool = models.BooleanField(
        default=False,
        help_text="Designates whether the user can log into this admin site.",
    )
    is_active: bool = models.BooleanField(
        default=True,
        help_text="Designates whether this user should be treated as active."
        " Unselect this instead of deleting accounts.",
    )
    date_joined = models.DateTimeField(default=timezone.now)

    is_verified: bool = models.BooleanField(
        default=False,
        help_text="Designates whether this user has completed the email "
        "verification process to allow login.",
    )

    USERNAME_FIELD: str = "email"
    REQUIRED_FIELDS: list = ["first_name", "last_name"]

    objects = UserManager()

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Send email to this user
        """
        send_mail(subject, message, from_email, [self.email], **kwargs)

    def __str__(self) -> str:
        return self.email
