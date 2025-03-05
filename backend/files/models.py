from django.db import models
from users.models import CustomUser

class File(models.Model):
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    encrypted_data = models.BinaryField()
    encryption_key = models.BinaryField()  # Encrypted with server's public key
    iv = models.BinaryField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    shared_with = models.ManyToManyField(CustomUser, related_name='shared_files', blank=True)
    can_download = models.BooleanField(default=False)

    def __str__(self):
        return f"File {self.id} owned by {self.owner.username}"
