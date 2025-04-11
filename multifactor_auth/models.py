from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, blank=True, null=True)
    security_question = models.CharField(max_length=255)
    security_answer = models.CharField(max_length=255)

    def __str__(self):
        return self.user.username
