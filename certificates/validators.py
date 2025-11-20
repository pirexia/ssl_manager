import re
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password
from .models import PasswordPolicy, PasswordHistory, Role

def validate_password_complexity(password, user):
    """
    Validates password complexity based on the user's role policy.
    """
    if not user.role:
        # Default policy if no role assigned (fallback to standard user requirements)
        min_length = 12
        require_uppercase = True
        require_lowercase = True
        require_numbers = True
        require_special_chars = True
    else:
        try:
            policy = user.role.passwordpolicy
            min_length = policy.min_length
            require_uppercase = policy.require_uppercase
            require_lowercase = policy.require_lowercase
            require_numbers = policy.require_numbers
            require_special_chars = policy.require_special_chars
            
            # Override min_length based on specific requirements if policy hasn't been updated
            if user.role.name == Role.ADMIN and min_length < 16:
                min_length = 16
            elif user.role.name == Role.USER and min_length < 12:
                min_length = 12
                
        except PasswordPolicy.DoesNotExist:
            # Fallback defaults if policy record missing
            if user.role.name == Role.ADMIN:
                min_length = 16
            else:
                min_length = 12
            require_uppercase = True
            require_lowercase = True
            require_numbers = True
            require_special_chars = True

    if len(password) < min_length:
        raise ValidationError(f"Password must be at least {min_length} characters long.")

    if require_uppercase and not any(char.isupper() for char in password):
        raise ValidationError("Password must contain at least one uppercase letter.")

    if require_lowercase and not any(char.islower() for char in password):
        raise ValidationError("Password must contain at least one lowercase letter.")

    if require_numbers and not any(char.isdigit() for char in password):
        raise ValidationError("Password must contain at least one number.")

    if require_special_chars and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValidationError("Password must contain at least one special character.")

def validate_password_history(password, user):
    """
    Validates that the password has not been used in the recent history.
    """
    try:
        policy = user.role.passwordpolicy
        history_length = policy.history_length
    except (AttributeError, PasswordPolicy.DoesNotExist):
        history_length = 20  # Default requirement

    # Get the last N passwords from history
    recent_passwords = PasswordHistory.objects.filter(user=user).order_by('-created_at')[:history_length]

    for history_entry in recent_passwords:
        if check_password(password, history_entry.password_hash):
            raise ValidationError(f"You cannot reuse any of your last {history_length} passwords.")
