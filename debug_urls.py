import os
import django
from django.conf import settings
from django.urls import get_resolver

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ssl_manager.settings')
django.setup()

def print_urls(resolver, prefix=''):
    for pattern in resolver.url_patterns:
        if hasattr(pattern, 'url_patterns'):
            print_urls(pattern, prefix + str(pattern.pattern))
        else:
            print(prefix + str(pattern.pattern))

print("Printing URL patterns:")
print_urls(get_resolver())
