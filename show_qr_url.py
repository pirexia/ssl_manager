import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ssl_manager.settings')
django.setup()

from django_otp.plugins.otp_totp.models import TOTPDevice
from certificates.models import User

# Get admin user
admin = User.objects.get(username='admin')

# Get the device
device = TOTPDevice.objects.filter(user=admin).first()

if device:
    print("="*60)
    print("QR CODE URL")
    print("="*60)
    print(f"\n{device.config_url}\n")
    print("="*60)
    print("\nThis is the URL encoded in the QR code.")
    print("It should contain:")
    print(f"  - Secret: {device.key}")
    print(f"  - Issuer: SSL Manager (or similar)")
    print(f"  - Account: {admin.username}")
    print("="*60)
else:
    print("No device found!")
