import os
import django
import base64

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ssl_manager.settings')
django.setup()

from django_otp.plugins.otp_totp.models import TOTPDevice
from certificates.models import User

# Get admin user
admin = User.objects.get(username='admin')

# Get the device
device = TOTPDevice.objects.filter(user=admin).first()

if device:
    # The key is stored as hex, convert to base32
    hex_key = device.key
    
    # Convert hex to bytes
    key_bytes = bytes.fromhex(hex_key)
    
    # Convert bytes to base32
    base32_key = base64.b32encode(key_bytes).decode('utf-8')
    
    print("="*60)
    print("TOTP SECRET KEY IN BASE32 FORMAT")
    print("="*60)
    print(f"\nSecret Key: {base32_key}")
    print(f"\n" + "="*60)
    print("INSTRUCTIONS:")
    print("="*60)
    print("\n1. DELETE the current 'SSL Manager' entry from your app")
    print("\n2. ADD A NEW ENTRY MANUALLY:")
    print(f"   - Account: admin@SSL Manager")
    print(f"   - Key: {base32_key}")
    print(f"   - Type: Time-based")
    print("\n3. Or just scan the QR code at /mfa/setup/")
    print("="*60)
else:
    print("No device found!")
