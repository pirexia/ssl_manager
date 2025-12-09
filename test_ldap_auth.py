import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ssl_manager.settings')
django.setup()

from django.contrib.auth import authenticate
from django.test import RequestFactory

# Create a dummy request
request = RequestFactory().get('/login/')
request.session = {}

# Test LDAP authentication
print("Attempting LDAP authentication for 'testuser'...")
user = authenticate(request, username='testuser', password='test123', auth_source='ldap')

if user:
    print(f"SUCCESS: Authenticated user: {user.username}")
    print(f"Auth Source in session: {request.session.get('auth_source')}")
    print(f"Backend: {user.backend}")
else:
    print("FAILURE: Authentication failed")

# Test Local authentication (should fail with LDAP password if not set locally, but let's just check LDAP for now)
# Note: testuser was created without a password in Django, so local auth should fail unless we set one.
