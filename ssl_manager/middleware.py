from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.contrib import messages
from certificates.models import PasswordPolicy, Role

class PasswordExpirationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Skip check for admin site, logout, and password change URL to avoid infinite loops
            current_path = request.path
            exempt_paths = [
                reverse('password_change'),
                reverse('logout'),
                '/admin/', # Skip admin for now to avoid locking out if something goes wrong
            ]
            
            if not any(current_path.startswith(path) for path in exempt_paths):
                # Check expiration
                try:
                    if request.user.role:
                        policy = request.user.role.passwordpolicy
                        expiry_days = policy.expiry_days
                    else:
                        expiry_days = 90 # Default
                except (AttributeError, PasswordPolicy.DoesNotExist):
                    expiry_days = 90

                last_changed = request.user.password_changed_at
                if last_changed:
                    # Calculate expiration date
                    expiration_date = last_changed + timezone.timedelta(days=expiry_days)
                    
                    if timezone.now() > expiration_date:
                        messages.warning(request, "Your password has expired. Please change it now.")
                        return redirect('password_change')
        
        response = self.get_response(request)
        return response
