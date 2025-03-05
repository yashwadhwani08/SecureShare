from celery import shared_task
from cryptography.fernet import Fernet
from .models import File

@shared_task
def encrypt_file(file_id):
    file = File.objects.get(id=file_id)
    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(file.temp_data)
    file.encrypted_data = encrypted_data
    file.encryption_key = key
    file.save()
