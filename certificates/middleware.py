from django.shortcuts import redirect
from django.urls import reverse
from django_otp.plugins.otp_totp.models import TOTPDevice

class MFAMiddleware:
    """Middleware to enforce MFA verification after login"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Skip MFA check for certain URLs
        exempt_urls = [
            reverse('login'),
            reverse('logout'),
            reverse('mfa_login'),
            reverse('mfa_setup'),
            reverse('mfa_verify_setup'),
        ]
        
        if request.path in exempt_urls:
            return self.get_response(request)
        
        # Check if user is authenticated and has MFA enabled
        if request.user.is_authenticated:
            device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
            
            if device:
                # Check if MFA verification is needed
                if not request.session.get('mfa_verified'):
                    # Check for trusted device
                    from .models import TrustedDevice
                    trusted_token = request.COOKIES.get('trusted_device')
                    
                    if trusted_token:
                        trusted_device = TrustedDevice.objects.filter(
                            user=request.user,
                            token=trusted_token
                        ).first()
                        
                        if trusted_device and trusted_device.is_valid():
                            # Mark as verified
                            request.session['mfa_verified'] = True
                        else:
                            # Redirect to MFA verification
                            return redirect('mfa_login')
                    else:
                        # No trusted device, need MFA
                        return redirect('mfa_login')
        
        response = self.get_response(request)
        return response
