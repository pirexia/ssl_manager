from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import PasswordHistory, PasswordPolicy

User = get_user_model()

@receiver(pre_save, sender=User)
def check_password_change(sender, instance, **kwargs):
    """
    Check if password is being changed.
    """
    if instance.pk:
        try:
            old_user = User.objects.get(pk=instance.pk)
            if old_user.password != instance.password:
                instance._password_changed = True
        except User.DoesNotExist:
            pass
    else:
        instance._password_changed = True

@receiver(post_save, sender=User)
def save_password_history(sender, instance, created, **kwargs):
    """
    Save password history if password changed.
    """
    if getattr(instance, '_password_changed', False):
        # Create history entry
        PasswordHistory.objects.create(
            user=instance,
            password_hash=instance.password
        )
        
        # Trim history
        try:
            if instance.role:
                policy = instance.role.passwordpolicy
                history_length = policy.history_length
            else:
                history_length = 20
        except (AttributeError, PasswordPolicy.DoesNotExist):
            history_length = 20
            
        # Keep only the last N entries
        history_ids = PasswordHistory.objects.filter(user=instance).order_by('-created_at').values_list('id', flat=True)[:history_length]
        PasswordHistory.objects.filter(user=instance).exclude(id__in=history_ids).delete()
