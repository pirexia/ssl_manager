from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

def generate_key_pair():
    """Generates a new RSA private key."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return key

def generate_csr(private_key, common_name, country=None, state=None, locality=None, organization=None, organizational_unit=None, email=None):
    """Generates a CSR using the private key and subject details."""

    subject_attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]

    if country:
        subject_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        subject_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organization:
        subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if organizational_unit:
        subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
    if email:
        subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(subject_attributes)
    ).sign(private_key, hashes.SHA256())

    return csr

def serialize_key(key):
    """Serializes private key to PEM format."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

def serialize_csr(csr):
    """Serializes CSR to PEM format."""
    return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def extract_certificate_dates(cert_content):
    """
    Extrae las fechas de validez de un certificado X.509.
    Args:
        cert_content: String con el contenido del certificado en formato PEM
    Returns:
        Tuple (valid_from, valid_until) as datetime objects
    """
    try:
        # Convertir string a bytes si es necesario
        if isinstance(cert_content, str):
            cert_content = cert_content.encode('utf-8')

        # Cargar el certificado
        cert = x509.load_pem_x509_certificate(cert_content)

        # Extraer fechas
        valid_from = cert.not_valid_before
        valid_until = cert.not_valid_after

        return (valid_from, valid_until)
    except Exception as e:
        raise ValueError(f"Error parsing certificate: {str(e)}")

def validate_certificate_matches_csr(cert_content, csr_content, expected_common_name):
    """
    Valida que el certificado corresponde al CSR generado.
    Verifica:
    1. Que el Common Name coincide
    2. Que la clave pública del certificado coincide con la del CSR

    Args:
        cert_content: String con el contenido del certificado
        csr_content: String con el contenido del CSR
        expected_common_name: Common name esperado

    Returns:
        Tuple (is_valid, error_message)
    """
    try:
        # Convertir a bytes si es necesario
        if isinstance(cert_content, str):
            cert_content = cert_content.encode('utf-8')
        if isinstance(csr_content, str):
            csr_content = csr_content.encode('utf-8')

        # Cargar certificado y CSR
        cert = x509.load_pem_x509_certificate(cert_content)
        csr = x509.load_pem_x509_csr(csr_content)

        # Validar Common Name
        cert_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cert_cn != expected_common_name:
            return (False, f"Common Name mismatch: expected '{expected_common_name}', got '{cert_cn}'")

        # Validar que la clave pública coincide
        cert_public_key = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        csr_public_key = csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if cert_public_key != csr_public_key:
            return (False, "Public key mismatch: certificate does not match CSR")

        return (True, "")
    except Exception as e:
        return (False, f"Validation error: {str(e)}")

def convert_certificate_format(cert_content, output_format):
    """
    Convierte el certificado a diferentes formatos.

    Args:
        cert_content: String con el contenido del certificado en PEM
        output_format: 'pem' o 'der'

    Returns:
        bytes del certificado en el formato solicitado
    """
    try:
        if isinstance(cert_content, str):
            cert_content = cert_content.encode('utf-8')

        cert = x509.load_pem_x509_certificate(cert_content)

        if output_format == 'pem':
            return cert.public_bytes(serialization.Encoding.PEM)
        elif output_format == 'der':
            return cert.public_bytes(serialization.Encoding.DER)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    except Exception as e:
        raise ValueError(f"Error converting certificate: {str(e)}")

def create_pfx(cert_content, private_key_content, password):
    """
    Crea un archivo PKCS#12 (.pfx) con certificado + clave privada.

    Args:
        cert_content: String con el contenido del certificado
        private_key_content: String con el contenido de la clave privada
        password: Contraseña para proteger el archivo PFX

    Returns:
        bytes del archivo PFX
    """
    from cryptography.hazmat.primitives.serialization import pkcs12

    try:
        if isinstance(cert_content, str):
            cert_content = cert_content.encode('utf-8')
        if isinstance(private_key_content, str):
            private_key_content = private_key_content.encode('utf-8')

        # Cargar certificado y clave privada
        cert = x509.load_pem_x509_certificate(cert_content)
        private_key = serialization.load_pem_private_key(
            private_key_content,
            password=None
        )

        # Crear PKCS#12
        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=None,
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )

        return pfx_bytes
    except Exception as e:
        raise ValueError(f"Error creating PFX: {str(e)}")

# Internal CA Functions

def generate_root_ca(ca_name="SSL Manager Root CA"):
    """
    Generate a self-signed root CA certificate.

    Args:
        ca_name: Name for the CA

    Returns:
        Tuple (root_cert, root_key) as cryptography objects
    """
    from datetime import datetime, timedelta

    # Generate key pair
    root_key = generate_key_pair()

    # Build subject/issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSL Manager"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])

    # Build certificate
    root_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(root_key, hashes.SHA256())

    return root_cert, root_key

def generate_intermediate_ca(root_cert, root_key, ca_name="SSL Manager Intermediate CA"):
    """
    Generate an intermediate CA certificate signed by the root CA.

    Args:
        root_cert: Root CA certificate
        root_key: Root CA private key
        ca_name: Name for the intermediate CA

    Returns:
        Tuple (intermediate_cert, intermediate_key) as cryptography objects
    """
    from datetime import datetime, timedelta

    # Generate key pair for intermediate
    intermediate_key = generate_key_pair()

    # Build subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSL Manager"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])

    # Build certificate signed by root
    intermediate_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        intermediate_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=1825)  # 5 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(root_key, hashes.SHA256())

    return intermediate_cert, intermediate_key

def get_or_create_internal_ca():
    """
    Get the active Internal CA or create one if it doesn't exist.

    Returns:
        InternalCA model instance
    """
    from .models import InternalCA

    # Try to get active CA
    ca = InternalCA.objects.filter(is_active=True).first()

    if ca:
        return ca

    # Generate new CA
    root_cert, root_key = generate_root_ca()
    intermediate_cert, intermediate_key = generate_intermediate_ca(root_cert, root_key)

    # Serialize to PEM
    root_cert_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    root_key_pem = serialize_key(root_key)
    intermediate_cert_pem = intermediate_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    intermediate_key_pem = serialize_key(intermediate_key)

    # Create and save CA
    ca = InternalCA.objects.create(
        name='SSL Manager Internal CA',
        root_ca_cert=root_cert_pem,
        root_ca_key=root_key_pem,
        intermediate_ca_cert=intermediate_cert_pem,
        intermediate_ca_key=intermediate_key_pem,
        is_active=True
    )

    return ca

def sign_csr_with_internal_ca(csr_pem, validity_days=365):
    """
    Sign a CSR with the internal CA.

    Args:
        csr_pem: CSR in PEM format (string)
        validity_days: Certificate validity period in days

    Returns:
        Certificate in PEM format (string)
    """
    from datetime import datetime, timedelta

    # Get or create CA
    ca = get_or_create_internal_ca()

    # Load CA certificates and keys
    intermediate_cert = x509.load_pem_x509_certificate(ca.intermediate_ca_cert.encode('utf-8'))
    intermediate_key = serialization.load_pem_private_key(
        ca.intermediate_ca_key.encode('utf-8'),
        password=None
    )

    # Load CSR
    if isinstance(csr_pem, str):
        csr_pem = csr_pem.encode('utf-8')
    csr = x509.load_pem_x509_csr(csr_pem)

    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        intermediate_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(intermediate_key, hashes.SHA256())

    # Return as PEM
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def create_certificate_bundle(cert_pem, intermediate_pem, root_pem):
    """
    Create a certificate bundle (chain) with leaf + intermediate + root.

    Args:
        cert_pem: Leaf certificate in PEM format
        intermediate_pem: Intermediate CA certificate in PEM format
        root_pem: Root CA certificate in PEM format

    Returns:
        Bundle as a single PEM string
    """
    return cert_pem + "\n" + intermediate_pem + "\n" + root_pem

