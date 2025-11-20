import os
import django
import time

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ssl_manager.settings')
django.setup()

from django_otp.plugins.otp_totp.models import TOTPDevice
from certificates.models import User

# Get admin user
admin = User.objects.get(username='admin')

# Get the device
device = TOTPDevice.objects.filter(user=admin).first()

if device:
    print(f"Device found: {device}")
    print(f"  - Confirmed: {device.confirmed}")
    print(f"  - Key: {device.key}")
    print(f"  - Digits: {device.digits}")
    print(f"  - Step: {device.step}")
    print(f"  - Drift: {device.drift}")
    print(f"  - T0: {device.t0}")
    print(f"\nCurrent server time: {int(time.time())}")
    
    # Generate the expected token
    from django_otp.oath import totp
    current_time = int(time.time())
    expected = totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits)
    print(f"\nExpected TOTP code RIGHT NOW: {expected}")
    
    # Test with a sample token
    print("\n" + "="*50)
    print("Enter the code from your authenticator app:")
    user_token = input("> ")
    
    result = device.verify_token(user_token)
    print(f"\nVerification result: {result}")
    
    if not result:
        print("\nTrying with time drift...")
        for drift in range(-2, 3):
            t = current_time + (drift * device.step)
            token_at_drift = totp(device.bin_key, t=t, step=device.step, t0=device.t0, digits=device.digits)
            print(f"  Drift {drift:+2d} ({drift*30:+4d}s): {token_at_drift} {'<-- MATCH!' if str(token_at_drift) == user_token else ''}")
else:
    print("No TOTP device found for admin user!")
    print("Please go to /mfa/setup/ first")
