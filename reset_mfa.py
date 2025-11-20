import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ssl_manager.settings')
django.setup()

from django_otp.plugins.otp_totp.models import TOTPDevice
from certificates.models import User

# Get admin user
admin = User.objects.get(username='admin')

# Delete all TOTP devices for admin (both confirmed and unconfirmed)
deleted_count = TOTPDevice.objects.filter(user=admin).delete()[0]

print(f"Deleted {deleted_count} TOTP device(s) for user 'admin'")
print("You can now set up MFA from scratch at /mfa/setup/")
