import os
import django
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ssl_manager.settings')
django.setup()

print(f"LANGUAGES: {settings.LANGUAGES}")
print(f"LANGUAGE_CODE: {settings.LANGUAGE_CODE}")
print(f"USE_I18N: {settings.USE_I18N}")
