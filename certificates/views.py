from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login_func
from django.contrib import messages

def login_view(request):
    """Custom login view that handles auth_source selection"""
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        auth_source = request.POST.get('auth_source', 'local')

        # Authenticate with the selected source
        user = authenticate(request, username=username, password=password, auth_source=auth_source)

        if user is not None:
            # Login successful
            auth_login_func(request, user, backend=f'certificates.backends.SourceAware{"LDAP" if auth_source == "ldap" else "Model"}Backend')
            # auth_source is already stored in session by the backend
            return redirect('mfa_login')  # Continue to MFA if enabled
        else:
            # Authentication failed
            messages.error(request, 'Invalid username, password, or authentication source.')
            return render(request, 'login.html')

    return render(request, 'login.html')


@login_required
def home(request):
    return render(request, 'home.html')

from .forms import CSRGenerationForm
from .utils import generate_key_pair, generate_csr as create_csr_object, serialize_key, serialize_csr
from .models import CertificateEntry, Domain

from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.conf import settings
import os

@login_required
@login_required
def generate_csr(request):
    # Get unique certificates for renewal dropdown (latest per common_name)
    from django.db.models import Max
    latest_ids = CertificateEntry.objects.values('common_name').annotate(
        latest_id=Max('id')
    ).values_list('latest_id', flat=True)
    existing_certs = CertificateEntry.objects.filter(id__in=latest_ids).order_by('common_name')

    if request.method == 'POST':
        # Check if this is a renewal request
        renew_cert_id = request.POST.get('renew_cert_id')

        if renew_cert_id:
            # Handle Renewal
            original_entry = get_object_or_404(CertificateEntry, pk=renew_cert_id)

            # Use data from original entry
            domain = original_entry.domain
            subdomain = original_entry.subdomain
            full_common_name = original_entry.common_name

            # Generate NEW Crypto Material
            key = generate_key_pair()

            # Create CSR using original entry's details
            csr = create_csr_object(
                key,
                full_common_name,
                country=original_entry.country,
                state=original_entry.state,
                locality=original_entry.locality,
                organization=original_entry.organization,
                organizational_unit=original_entry.organizational_unit,
                email=original_entry.email_address
            )

            # Serialize
            pem_key = serialize_key(key)
            pem_csr = serialize_csr(csr)

            # Save new entry
            entry = CertificateEntry(
                common_name=full_common_name,
                domain=domain,
                subdomain=subdomain,
                csr_content=pem_csr,
                private_key_content=pem_key,
                created_by=request.user,
                # Copy attributes
                country=original_entry.country,
                state=original_entry.state,
                locality=original_entry.locality,
                organization=original_entry.organization,
                organizational_unit=original_entry.organizational_unit,
                email_address=original_entry.email_address
            )
            entry.save()

            # Save to Storage
            storage_dir = os.path.join(settings.BASE_DIR, 'storage', entry.common_name)
            os.makedirs(storage_dir, exist_ok=True)
            timestamp = entry.created_at.strftime('%Y%m%d_%H%M%S')

            with open(os.path.join(storage_dir, f"{timestamp}.key"), 'w') as f:
                f.write(pem_key)

            with open(os.path.join(storage_dir, f"{timestamp}.csr"), 'w') as f:
                f.write(pem_csr)

            return render(request, 'csr_result.html', {'entry': entry})

        else:
            # Standard Generation
            form = CSRGenerationForm(request.POST)
            if form.is_valid():
                # Extract data
                domain = form.cleaned_data['domain']
                subdomain = form.cleaned_data['subdomain']
                full_common_name = f"{subdomain}.{domain.name}"

                # Generate Crypto Material
                key = generate_key_pair()

                # Use attributes from the selected Domain object
                csr = create_csr_object(
                    key,
                    full_common_name,
                    country=domain.country,
                    state=domain.state,
                    locality=domain.locality,
                    organization=domain.organization,
                    organizational_unit=domain.organizational_unit,
                    email=domain.email_address
                )

                # Serialize
                pem_key = serialize_key(key)
                pem_csr = serialize_csr(csr)

                # Save to DB
                entry = form.save(commit=False)
                entry.common_name = full_common_name
                entry.csr_content = pem_csr
                entry.private_key_content = pem_key
                entry.created_by = request.user
                # Copy domain attributes to certificate entry
                entry.organization = domain.organization
                entry.organizational_unit = domain.organizational_unit
                entry.locality = domain.locality
                entry.state = domain.state
                entry.country = domain.country
                entry.save()

                # Save to Storage Directory (organized by common_name)
                storage_dir = os.path.join(settings.BASE_DIR, 'storage', entry.common_name)
                os.makedirs(storage_dir, exist_ok=True)

                # Use timestamp as unique identifier for this iteration
                timestamp = entry.created_at.strftime('%Y%m%d_%H%M%S')

                with open(os.path.join(storage_dir, f"{timestamp}.key"), 'w') as f:
                    f.write(pem_key)

                with open(os.path.join(storage_dir, f"{timestamp}.csr"), 'w') as f:
                    f.write(pem_csr)

                return render(request, 'csr_result.html', {'entry': entry})
    else:
        form = CSRGenerationForm()

    return render(request, 'generate_csr.html', {
        'form': form,
        'existing_certs': existing_certs
    })

@login_required
def get_domain_details(request, domain_id):
    try:
        domain = Domain.objects.get(pk=domain_id)
        data = {
            'country': domain.country,
            'state': domain.state,
            'locality': domain.locality,
            'organization': domain.organization,
            'organizational_unit': domain.organizational_unit,
            'email_address': domain.email_address,
        }
        return JsonResponse(data)
    except Domain.DoesNotExist:
        return JsonResponse({'error': 'Domain not found'}, status=404)

@login_required
def search_certificates(request):
    from django.core.paginator import Paginator
    from django.utils import timezone
    from datetime import timedelta
    from django.db.models import Max

    # Get all certificates by default
    results = CertificateEntry.objects.all()

    # Text search filter
    query = request.GET.get('q', '')
    if query:
        results = results.filter(common_name__icontains=query)

    # Domain filter (multi-select)
    domain_ids = request.GET.getlist('domains')
    if domain_ids:
        results = results.filter(domain_id__in=domain_ids)

    # Get only the latest entry for each common_name
    # First, get the latest ID for each common_name
    latest_entries = results.values('common_name').annotate(
        latest_id=Max('id')
    ).values_list('latest_id', flat=True)

    # Filter to only include these latest entries
    results = CertificateEntry.objects.filter(id__in=latest_entries)

    # Expiration filters
    expiry_filter = request.GET.get('expiry', '')
    if expiry_filter == '3months':
        three_months = timezone.now() + timedelta(days=90)
        results = results.filter(valid_until__lte=three_months, valid_until__gte=timezone.now())
    elif expiry_filter == '1month':
        one_month = timezone.now() + timedelta(days=30)
        results = results.filter(valid_until__lte=one_month, valid_until__gte=timezone.now())

    # Sorting
    sort_by = request.GET.get('sort', '-created_at')
    valid_sorts = ['common_name', '-common_name', 'created_at', '-created_at', 'valid_until', '-valid_until']
    if sort_by in valid_sorts:
        results = results.order_by(sort_by)
    else:
        results = results.order_by('-created_at')

    # Pagination
    per_page = request.GET.get('per_page', '10')
    try:
        per_page = int(per_page)
        if per_page not in [10, 25, 50, 100]:
            per_page = 10
    except ValueError:
        per_page = 10

    paginator = Paginator(results, per_page)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # Get all domains for filter dropdown
    domains = Domain.objects.all()

    return render(request, 'search.html', {
        'page_obj': page_obj,
        'query': query,
        'domains': domains,
        'selected_domains': domain_ids,
        'expiry_filter': expiry_filter,
        'sort_by': sort_by,
        'per_page': per_page,
    })

@login_required
def certificate_detail(request, pk):
    entry = get_object_or_404(CertificateEntry, pk=pk)
    # Get all iterations for this common_name
    iterations = CertificateEntry.objects.filter(common_name=entry.common_name).order_by('-created_at')
    return render(request, 'certificate_detail.html', {'entry': entry, 'iterations': iterations})

@login_required
def download_file(request, pk, file_type):
    entry = get_object_or_404(CertificateEntry, pk=pk)

    if file_type == 'csr':
        content = entry.csr_content
        filename = f"{entry.common_name}.csr"
    elif file_type == 'key':
        content = entry.private_key_content
        filename = f"{entry.common_name}.key"
    else:
        return HttpResponse(status=404)

    response = HttpResponse(content, content_type='text/plain')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

from .forms import CertificateUploadForm, CustomPasswordChangeForm
from .utils import extract_certificate_dates, validate_certificate_matches_csr, convert_certificate_format, create_pfx
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash

@login_required
def upload_certificate(request, pk):
    """Vista para subir el certificado final a una CertificateEntry existente"""
    entry = get_object_or_404(CertificateEntry, pk=pk)

    if request.method == 'POST':
        form = CertificateUploadForm(request.POST, request.FILES)
        if form.is_valid():
            cert_file = form.cleaned_data['certificate_file']
            cert_content = cert_file.read().decode('utf-8')

            # Validar que el certificado corresponde al CSR
            is_valid, error_msg = validate_certificate_matches_csr(
                cert_content,
                entry.csr_content,
                entry.common_name
            )

            if not is_valid:
                messages.error(request, f"Certificate validation failed: {error_msg}")
                return redirect('certificate_detail', pk=pk)

            # Extraer fechas de validez
            try:
                valid_from, valid_until = extract_certificate_dates(cert_content)
            except ValueError as e:
                messages.error(request, str(e))
                return redirect('certificate_detail', pk=pk)

            # Guardar certificado en storage
            storage_dir = os.path.join(settings.BASE_DIR, 'storage', entry.common_name)
            os.makedirs(storage_dir, exist_ok=True)
            timestamp = entry.created_at.strftime('%Y%m%d_%H%M%S')
            cert_path = os.path.join(storage_dir, f"{timestamp}.crt")

            with open(cert_path, 'w') as f:
                f.write(cert_content)

            # Actualizar entrada en la base de datos
            entry.certificate_content = cert_content
            entry.valid_from = valid_from
            entry.valid_until = valid_until
            entry.status = CertificateEntry.STATUS_ISSUED
            entry.save()

            messages.success(request, 'Certificate uploaded successfully!')
            return redirect('certificate_detail', pk=pk)

    # Si es GET, redirigir a la vista de detalle
    return redirect('certificate_detail', pk=pk)

@login_required
def download_certificate(request, pk, format):
    """Descargar certificado en diferentes formatos"""
    entry = get_object_or_404(CertificateEntry, pk=pk)

    if not entry.certificate_content:
        return HttpResponse("No certificate available", status=404)

    if format == 'crt':
        # Formato PEM (.crt)
        content = convert_certificate_format(entry.certificate_content, 'pem')
        filename = f"{entry.common_name}.crt"
        content_type = 'application/x-pem-file'
    elif format == 'cer':
        # Formato DER (.cer)
        content = convert_certificate_format(entry.certificate_content, 'der')
        filename = f"{entry.common_name}.cer"
        content_type = 'application/x-x509-ca-cert'
    elif format == 'pem':
        # Formato PEM (.pem)
        content = convert_certificate_format(entry.certificate_content, 'pem')
        filename = f"{entry.common_name}.pem"
        content_type = 'application/x-pem-file'
    elif format == 'pfx':
        # Formato PKCS#12 (.pfx) - requiere contraseña
        if request.method == 'POST':
            password = request.POST.get('pfx_password', '')
            if not password:
                messages.error(request, 'Password required for PFX export')
                return redirect('certificate_detail', pk=pk)

            try:
                content = create_pfx(
                    entry.certificate_content,
                    entry.private_key_content,
                    password
                )
                filename = f"{entry.common_name}.pfx"
                content_type = 'application/x-pkcs12'
            except ValueError as e:
                messages.error(request, f'Error creating PFX: {str(e)}')
                return redirect('certificate_detail', pk=pk)
        else:
            messages.error(request, 'PFX download requires POST request with password')
            return redirect('certificate_detail', pk=pk)
    elif format == 'bundle':
        # Certificate bundle (only for internal certificates)
        if not entry.is_internal:
            messages.error(request, 'Bundle download is only available for internally-generated certificates')
            return redirect('certificate_detail', pk=pk)

        from .utils import create_certificate_bundle, get_or_create_internal_ca

        ca = get_or_create_internal_ca()
        content = create_certificate_bundle(
            entry.certificate_content,
            ca.intermediate_ca_cert,
            ca.root_ca_cert
        ).encode('utf-8')
        filename = f"{entry.common_name}_bundle.crt"
        content_type = 'application/x-x509-ca-cert'
    else:
        return HttpResponse("Invalid format", status=400)

    response = HttpResponse(content, content_type=content_type)
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

@login_required
def password_change_view(request):
    # Check if user logged in via LDAP
    if request.session.get('auth_source') == 'ldap':
        messages.error(request, 'LDAP users cannot change their password here. Please contact your system administrator.')
        return redirect('home')

    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('home')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = CustomPasswordChangeForm(request.user)
    return render(request, 'password_change.html', {'form': form})

# MFA Views
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from django.contrib.auth import login as auth_login
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
from .models import TrustedDevice
from django.utils import timezone
from datetime import timedelta
import secrets

@login_required
def mfa_setup(request):
    """Generate TOTP device and display QR code"""
    # Check if user already has ANY device (confirmed or not)
    device = TOTPDevice.objects.filter(user=request.user).first()

    if not device:
        # Create a new device only if none exists
        device = TOTPDevice.objects.create(
            user=request.user,
            name='default',
            confirmed=False
        )

    # Generate QR code
    url = device.config_url
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'mfa/setup.html', {
        'qr_code': img_str,
        'secret_key': device.key,
        'device': device
    })

@login_required
def mfa_verify_setup(request):
    """Verify the TOTP token to confirm device setup"""
    if request.method == 'POST':
        token = request.POST.get('token')
        device = TOTPDevice.objects.filter(user=request.user, confirmed=False).first()

        # Simple verification - django-otp handles time drift internally
        if device and device.verify_token(token):
            device.confirmed = True
            device.save()
            messages.success(request, 'MFA has been successfully enabled!')
            return redirect('home')
        else:
            messages.error(request, 'Invalid token. Please try again.')

    return redirect('mfa_setup')

def mfa_login_view(request):
    """Handle MFA token verification during login"""
    if not request.user.is_authenticated:
        return redirect('login')

    # Check for trusted device
    trusted_token = request.COOKIES.get('trusted_device')
    if trusted_token:
        trusted_device = TrustedDevice.objects.filter(
            user=request.user,
            token=trusted_token
        ).first()

        if trusted_device and trusted_device.is_valid():
            # Skip MFA
            return redirect('home')

    # Check if user has MFA enabled
    device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
    if not device:
        # No MFA setup, redirect to home
        return redirect('home')

    if request.method == 'POST':
        token = request.POST.get('token')
        trust_device = request.POST.get('trust_device') == 'on'

        # Simple verification - django-otp handles time drift internally
        if device.verify_token(token):
            # MFA successful - mark session as verified
            request.session['mfa_verified'] = True
            response = redirect('home')

            # Create trusted device if requested
            if trust_device:
                device_token = secrets.token_urlsafe(32)
                user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]

                TrustedDevice.objects.create(
                    user=request.user,
                    token=device_token,
                    expires_at=timezone.now() + timedelta(days=7),
                    user_agent=user_agent
                )

                # Set cookie (7 days)
                response.set_cookie(
                    'trusted_device',
                    device_token,
                    max_age=7*24*60*60,
                    httponly=True,
                    secure=False  # Set to True in production with HTTPS
                )

            messages.success(request, 'Login successful!')
            return response
        else:
            messages.error(request, 'Invalid authentication code.')

    # Check cookie consent
    cookies_accepted = get_cookie_consent(request)

    return render(request, 'mfa/verify.html', {
        'cookies_accepted': cookies_accepted
    })

# Cookie Consent
from .models import CookieConsent
from django.http import JsonResponse

def set_cookie_consent(request):
    """Handle cookie consent acceptance/rejection"""
    if request.method == 'POST':
        accept = request.POST.get('accept') == 'true'

        # Ensure session exists
        if not request.session.session_key:
            request.session.create()

        session_key = request.session.session_key
        user = request.user if request.user.is_authenticated else None

        # Create or update consent
        consent, created = CookieConsent.objects.update_or_create(
            session_key=session_key,
            defaults={
                'user': user,
                'optional_cookies_accepted': accept
            }
        )

        return JsonResponse({'success': True, 'accepted': accept})

    return JsonResponse({'success': False}, status=400)

def get_cookie_consent(request):
    """Check if user has accepted optional cookies"""
    if not request.session.session_key:
        return None

    try:
        consent = CookieConsent.objects.get(session_key=request.session.session_key)
        return consent.optional_cookies_accepted
    except CookieConsent.DoesNotExist:
        return None

# Language Preference
from django.utils import translation
from django.utils.translation import check_for_language
from django.urls import translate_url, resolve, reverse
from django.shortcuts import redirect
from django.conf import settings
from django.http import HttpResponseRedirect
from urllib.parse import urlparse

def set_language(request):
    """
    Custom set_language view that:
    1. Saves preference to database for authenticated users
    2. Sets the django_language cookie and session
    3. Redirects to the URL with the correct language prefix
    """
    next_url = request.POST.get('next') or request.META.get('HTTP_REFERER') or '/'
    response = HttpResponseRedirect(next_url)

    if request.method == 'POST':
        lang_code = request.POST.get('language')

        if lang_code and check_for_language(lang_code):
            # 1. Save to database for authenticated users
            if request.user.is_authenticated:
                request.user.preferred_language = lang_code
                request.user.save(update_fields=['preferred_language'])

            # 2. Calculate new URL with prefix
            try:
                # Parse URL to get path
                parsed = urlparse(next_url)
                path = parsed.path

                # Resolve current view
                match = resolve(path)

                # Reverse with new language
                with translation.override(lang_code):
                    if match.namespaces:
                        view_name = f"{':'.join(match.namespaces)}:{match.url_name}"
                    else:
                        view_name = match.url_name

                    new_url = reverse(view_name, args=match.args, kwargs=match.kwargs)

                    # Preserve query parameters
                    if parsed.query:
                        new_url += f"?{parsed.query}"

                    response = HttpResponseRedirect(new_url)
            except Exception:
                # Fallback to translate_url or original url
                new_url = translate_url(next_url, lang_code)
                if new_url:
                    response = HttpResponseRedirect(new_url)

            # 3. Set session language
            if hasattr(request, 'session'):
                request.session['_language'] = lang_code

            # 4. Set language cookie
            response.set_cookie(
                settings.LANGUAGE_COOKIE_NAME, lang_code,
                max_age=settings.LANGUAGE_COOKIE_AGE,
                path=settings.LANGUAGE_COOKIE_PATH,
                domain=settings.LANGUAGE_COOKIE_DOMAIN,
                secure=settings.LANGUAGE_COOKIE_SECURE,
                httponly=settings.LANGUAGE_COOKIE_HTTPONLY,
                samesite=settings.LANGUAGE_COOKIE_SAMESITE,
            )

    return response
@login_required
def generate_internal_certificate(request, pk):
    """Generate and sign certificate using internal CA"""
    if request.method != 'POST':
        return redirect('certificate_detail', pk=pk)

    entry = get_object_or_404(CertificateEntry, pk=pk)

    # Check if certificate already exists
    if entry.certificate_content:
        messages.warning(request, 'Certificate already exists for this entry')
        return redirect('certificate_detail', pk=pk)

    try:
        from .utils import sign_csr_with_internal_ca, extract_certificate_dates

        # Sign CSR with internal CA
        cert_content = sign_csr_with_internal_ca(entry.csr_content, validity_days=365)

        # Extract dates
        valid_from, valid_until = extract_certificate_dates(cert_content)

        # Update entry
        entry.certificate_content = cert_content
        entry.valid_from = valid_from
        entry.valid_until = valid_until
        entry.status = CertificateEntry.STATUS_ISSUED
        entry.is_internal = True
        entry.save()

        messages.success(request, 'Certificate generated successfully with Internal CA!')

    except Exception as e:
        messages.error(request, f'Error generating certificate: {str(e)}')

    return redirect('certificate_detail', pk=pk)


@login_required
def download_ca_certificate(request, ca_type):
    """Download Root or Intermediate CA certificate"""
    from .utils import get_or_create_internal_ca

    ca = get_or_create_internal_ca()

    if ca_type == 'root':
        content = ca.root_ca_cert
        filename = "SSL_Manager_Root_CA.crt"
    elif ca_type == 'intermediate':
        content = ca.intermediate_ca_cert
        filename = "SSL_Manager_Intermediate_CA.crt"
    else:
        return HttpResponse("Invalid CA type", status=400)

    response = HttpResponse(content, content_type='application/x-x509-ca-cert')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
@login_required
def delete_certificate(request, pk):
    """Delete the certificate content from an entry, resetting it to PENDING"""
    if request.method != 'POST':
        return redirect('certificate_detail', pk=pk)

    entry = get_object_or_404(CertificateEntry, pk=pk)

    if not entry.certificate_content:
        messages.warning(request, 'No certificate to delete')
        return redirect('certificate_detail', pk=pk)

    try:
        # Clear certificate data
        entry.certificate_content = None
        entry.valid_from = None
        entry.valid_until = None
        entry.is_internal = False
        entry.status = CertificateEntry.STATUS_PENDING
        entry.save()

        messages.success(request, 'Certificate deleted successfully. You can now upload a new one or generate it internally.')
    except Exception as e:
        messages.error(request, f'Error deleting certificate: {str(e)}')

    return redirect('certificate_detail', pk=pk)
