from django.test import TestCase
from django.contrib.auth import get_user_model
from .models import CertificateEntry, Domain, InternalCA
from .utils import (
    generate_csr,
    sign_csr_with_internal_ca,
    get_or_create_internal_ca,
    create_certificate_bundle,
    extract_certificate_dates
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend

User = get_user_model()

class InternalCATest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='password')
        self.domain = Domain.objects.create(name='example.com', organization='Test Org')

    def test_internal_ca_generation(self):
        """Test that Internal CA is created correctly"""
        ca = get_or_create_internal_ca()
        self.assertIsNotNone(ca.root_ca_key)
        self.assertIsNotNone(ca.root_ca_cert)
        self.assertIsNotNone(ca.intermediate_ca_key)
        self.assertIsNotNone(ca.intermediate_ca_cert)
        self.assertTrue(ca.is_active)

    def test_certificate_signing(self):
        """Test signing a CSR with the internal CA"""
        from .utils import generate_key_pair, serialize_key, serialize_csr

        # 1. Generate Key and CSR
        key = generate_key_pair()
        csr = generate_csr(
            private_key=key,
            common_name='test.example.com',
            country='US',
            state='Test State',
            locality='Test City',
            organization='Test Org',
            organizational_unit='IT',
            email='admin@example.com'
        )

        csr_pem = serialize_csr(csr)
        key_pem = serialize_key(key)

        # 2. Create Entry
        entry = CertificateEntry.objects.create(
            common_name='test.example.com',
            domain=self.domain,
            csr_content=csr_pem,
            private_key_content=key_pem,
            created_by=self.user
        )

        # 3. Sign with Internal CA
        cert_pem = sign_csr_with_internal_ca(csr_pem)
        self.assertIsNotNone(cert_pem)

        # 4. Verify Certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
        self.assertEqual(cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, 'test.example.com')
        self.assertEqual(cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, 'SSL Manager Intermediate CA')

        # 5. Update Entry
        valid_from, valid_until = extract_certificate_dates(cert_pem)
        entry.certificate_content = cert_pem
        entry.valid_from = valid_from
        entry.valid_until = valid_until
        entry.is_internal = True
        entry.save()

        self.assertTrue(entry.is_internal)

        # 6. Test Bundle
        ca = get_or_create_internal_ca()
        bundle = create_certificate_bundle(cert_pem, ca.intermediate_ca_cert, ca.root_ca_cert)

        # Count certificates in bundle (should be 3)
        certs_in_bundle = bundle.count('-----BEGIN CERTIFICATE-----')
        self.assertEqual(certs_in_bundle, 3)
