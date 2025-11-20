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
