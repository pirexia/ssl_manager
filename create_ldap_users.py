import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ssl_manager.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

users = ['testuser', 'ldapuser', 'adminuser']

for username in users:
    if not User.objects.filter(username=username).exists():
        User.objects.create_user(username=username, email=f'{username}@sslmanager.local')
        print(f"Created user: {username}")
    else:
        print(f"User already exists: {username}")
