from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import User, Role, Domain, CertificateEntry, PasswordPolicy, PasswordHistory, TrustedDevice, CookieConsent

# Custom User Admin
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'is_staff')
    list_filter = ('role', 'is_staff', 'is_superuser', 'is_active')
    fieldsets = UserAdmin.fieldsets + (
        ('Role & Security', {'fields': ('role',)}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Role & Security', {'fields': ('role',)}),
    )

admin.site.register(User, CustomUserAdmin)

# Password Policy Inline
class PasswordPolicyInline(admin.StackedInline):
    model = PasswordPolicy
    can_delete = False
    verbose_name_plural = 'Password Policy'

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    inlines = (PasswordPolicyInline,)
    list_display = ('name', 'get_policy_summary')

    def get_policy_summary(self, obj):
        try:
            p = obj.passwordpolicy
            return f"Min: {p.min_length}, Exp: {p.expiry_days}d, Hist: {p.history_length}"
        except PasswordPolicy.DoesNotExist:
            return "No Policy"
    get_policy_summary.short_description = "Policy Summary"

@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'country', 'created_at')
    search_fields = ('name', 'organization')
    list_filter = ('country',)

@admin.register(CertificateEntry)
class CertificateEntryAdmin(admin.ModelAdmin):
    list_display = ('common_name', 'domain', 'status_colored', 'valid_from', 'valid_until', 'created_by', 'created_at')
    list_filter = ('status', 'domain', 'created_at')
    search_fields = ('common_name', 'csr_content', 'domain__name')
    readonly_fields = ('csr_content', 'private_key_content', 'certificate_content', 'created_at', 'created_by')
    actions = ['revoke_certificates']
    
    fieldsets = (
        ('Metadata', {
            'fields': ('common_name', 'domain', 'subdomain', 'status', 'created_by', 'created_at')
        }),
        ('Subject Attributes', {
            'fields': ('country', 'state', 'locality', 'organization', 'organizational_unit', 'email_address')
        }),
        ('Validity', {
            'fields': ('valid_from', 'valid_until')
        }),
        ('Content (Read-Only)', {
            'fields': ('csr_content', 'private_key_content', 'certificate_content'),
            'classes': ('collapse',)
        }),
    )

    def status_colored(self, obj):
        colors = {
            'PENDING': 'orange',
            'ISSUED': 'green',
            'SIGNED': 'blue',
            'REVOKED': 'red',
        }
        color = colors.get(obj.status, 'black')
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.get_status_display())
    status_colored.short_description = 'Status'

    def revoke_certificates(self, request, queryset):
        rows_updated = queryset.update(status=CertificateEntry.STATUS_REVOKED)
        if rows_updated == 1:
            message_bit = "1 certificate was"
        else:
            message_bit = f"{rows_updated} certificates were"
        self.message_user(request, f"{message_bit} successfully marked as revoked.")
    revoke_certificates.short_description = "Revoke selected certificates"

@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at')
    list_filter = ('user', 'created_at')
    readonly_fields = ('user', 'password_hash', 'created_at')
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False

@admin.register(TrustedDevice)
class TrustedDeviceAdmin(admin.ModelAdmin):
    list_display = ('user', 'user_agent', 'expires_at', 'last_used', 'is_valid')
    list_filter = ('user', 'expires_at')
    readonly_fields = ('user', 'token', 'user_agent', 'expires_at', 'last_used')
    
    def is_valid(self, obj):
        return obj.is_valid()
    is_valid.boolean = True
    is_valid.short_description = 'Valid'
    
    def has_add_permission(self, request):
        return False

@admin.register(CookieConsent)
class CookieConsentAdmin(admin.ModelAdmin):
    list_display = ('get_identifier', 'optional_cookies_accepted', 'created_at', 'updated_at')
    list_filter = ('optional_cookies_accepted', 'created_at')
    readonly_fields = ('session_key', 'user', 'created_at', 'updated_at')
    
    def get_identifier(self, obj):
        if obj.user:
            return f"User: {obj.user.username}"
        return f"Session: {obj.session_key[:8]}..."
    get_identifier.short_description = 'Identifier'
    
    def has_add_permission(self, request):
        return False
