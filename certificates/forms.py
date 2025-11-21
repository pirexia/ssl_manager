from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from .models import Domain, CertificateEntry
from .validators import validate_password_complexity, validate_password_history
from cryptography import x509
from django.utils.translation import gettext_lazy as _

class CSRGenerationForm(forms.ModelForm):
    domain = forms.ModelChoiceField(queryset=Domain.objects.all(), empty_label=_("Select Domain"), widget=forms.Select(attrs={'class': 'form-select'}))
    subdomain = forms.CharField(max_length=100, required=True, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': _('e.g. app1')}))
    
    class Meta:
        model = CertificateEntry
        fields = ['domain', 'subdomain']

class CertificateUploadForm(forms.Form):
    certificate_file = forms.FileField(
        label=_('Certificate File'),
        help_text=_('Upload certificate (.crt, .cer, .pem)'),
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.crt,.cer,.pem'})
    )
    
    def clean_certificate_file(self):
        file = self.cleaned_data.get('certificate_file')
        
        if not file:
            raise forms.ValidationError("No file provided")
        
        # Validar extensión
        allowed_extensions = ['.crt', '.cer', '.pem']
        file_ext = file.name[file.name.rfind('.'):].lower() if '.' in file.name else ''
        if file_ext not in allowed_extensions:
            raise forms.ValidationError(f"Invalid file extension. Allowed: {', '.join(allowed_extensions)}")
        
        # Leer contenido
        content = file.read()
        file.seek(0)  # Reset file pointer
        
        # Validar que es un certificado X.509 válido
        try:
            x509.load_pem_x509_certificate(content)
        except Exception as e:
            raise forms.ValidationError(f"Invalid certificate file: {str(e)}")
        
        return file

class CustomPasswordChangeForm(PasswordChangeForm):
    def clean_new_password1(self):
        password = self.cleaned_data.get('new_password1')
        user = self.user
        
        # Validate complexity
        validate_password_complexity(password, user)
        
        # Validate history
        validate_password_history(password, user)
        
        return password
