"""
Unit tests for CSR creation objects
"""

from base64 import b64decode
from tempfile import NamedTemporaryFile
from unittest import TestCase

from cryptography import x509
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.backends.openssl.x509 import _CertificateSigningRequest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

import autocsr.protos.csr_pb2 as protos
from autocsr.csr import (
    Attribute,
    CertificateSigningRequest,
    CertificateSigningRequestBuilder,
    MyBackend,
    PrivateKey,
    SigningKey,
    Subject,
)
from autocsr.oid import ObjectIdentifier
from autocsr.utils import load_csr

HashType = protos.CertificateSigningRequest.HashType


class TestAttribute(TestCase):
    """
    Test creation of Attributes
    """

    subject_fields = [
        "common_name",
        "country_name",
        "state_or_province_name",
        "locality_name",
        "organization_name",
        "organizational_unit_name",
        "email_address",
    ]
    subject_dict = {
        "common_name": "test common name",
        "country_name": "TC",
        "state_or_province_name": "test state or province",
        "locality_name": "test locality",
        "organization_name": "test organization",
        "organizational_unit_name": "test organizational unit",
        "email_address": "test@emailaddress.com",
    }

    def validate_attribute(self, attribute: Attribute):
        """
        Helper function for validating an attribute
        """

        self.assertIsInstance(
            attribute,
            x509.NameAttribute,
            "Attribute must be an instance of x509 NameAttribute",
        )

    def test_from_field(self):
        """
        Test creation of an x509 attribute from a field and value
        """

        for field in self.subject_fields:
            value = self.subject_dict.get(field)
            attribute = Attribute.from_field(field, value)

            self.validate_attribute(attribute)


class TestSubject(TestCase):
    """
    Test creation of Subject object
    """

    config = {
        "subject": TestAttribute.subject_dict,
        "key_path": "./fixtures/test.key",
        "output_path": "./fixtures/test.csr",
        "hash_type": "SHA512",
        "attributes": [
            {"oid": "2.5.29.17", "b64_value": "dGVzdA=="},
            {"oid": "issuerAltName", "b64_value": "aGk="},
        ],
    }

    def setUp(self):
        self.proto = load_csr(self.config)

    def validate_subject(self, subject: Subject):
        """
        A helper function for validating an x509 Name
        """

        self.assertIsInstance(
            subject,
            x509.Name,
            "Attribute must be an instance of x509 NameAttribute",
        )

    def test_from_subject(self):
        """
        Test creation of an x509.Name from a config file
        """

        subject = Subject.from_subject(self.proto.subject)

        self.validate_subject(subject)


class TestSigningKey(TestCase):
    """
    Tests for creating a Signing Key from a config file
    """

    def setUp(self):
        self.rsa_key_path = NamedTemporaryFile().name
        self.dsa_key_path = NamedTemporaryFile().name
        self.ec_key_path = NamedTemporaryFile().name

        self.rsa_private_key = self.create_rsa_key()

        self.dsa_private_key = dsa.generate_private_key(
            key_size=2048,
        )

        self.ec_private_key = ec.generate_private_key(
            ec.SECP384R1(),
        )

        self.write_key(self.rsa_key_path, self.rsa_private_key)
        self.write_key(self.dsa_key_path, self.dsa_private_key)
        self.write_key(self.ec_key_path, self.ec_private_key)

        self.approved_hashes = {
            HashType.SHA256: hashes.SHA256,
            HashType.SHA224: hashes.SHA224,
            HashType.SHA384: hashes.SHA384,
            HashType.SHA512: hashes.SHA512,
            HashType.SHA512_224: hashes.SHA512_224,
            HashType.SHA512_256: hashes.SHA512_256,
            HashType.BLAKE2b: hashes.BLAKE2b,
            HashType.BLAKE2s: hashes.BLAKE2s,
            HashType.SHA3_224: hashes.SHA3_224,
            HashType.SHA3_256: hashes.SHA3_256,
            HashType.SHA3_384: hashes.SHA3_384,
            HashType.SHA3_512: hashes.SHA3_512,
        }

    @staticmethod
    def create_rsa_key():
        """
        Helper function for generating RSA keys
        """

        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    @staticmethod
    def write_key(key_path: str, private_key: PrivateKey):
        """
        A helper function for writing a private key to a temporary file
        """

        with open(key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    def validate_signing_key(
        self,
        signing_key: SigningKey,
        key: PrivateKey,
        hash_type: HashType,
    ):
        """
        A helper function for validating signing key objects
        """

        self.assertIsInstance(
            signing_key.private_key,
            type(key),
            "Private Key type should be automatically associated",
        )
        self.assertEqual(
            signing_key.private_key.private_numbers(),
            key.private_numbers(),
            "Private keys should be equal",
        )
        self.assertIsInstance(
            signing_key.algorithm,
            self.approved_hashes[hash_type],
            "Hash should match selected hash type",
        )

    def test_from_path(self):
        """
        Test the creation of a SigningKey from a key file
        """

        for hash_type in self.approved_hashes:
            rsa_signing_key = SigningKey.from_path(self.rsa_key_path, hash_type)
            dsa_signing_key = SigningKey.from_path(self.dsa_key_path, hash_type)
            ec_signing_key = SigningKey.from_path(self.ec_key_path, hash_type)

            self.validate_signing_key(rsa_signing_key, self.rsa_private_key, hash_type)
            self.validate_signing_key(dsa_signing_key, self.dsa_private_key, hash_type)
            self.validate_signing_key(ec_signing_key, self.ec_private_key, hash_type)


class TestCertificateSigningRequest(TestCase):
    """
    Tests for x509 CertificateSigningRequest wrapper
    """

    def setUp(self):
        proto = load_csr(TestSubject.config)
        proto.key_path = self.create_rsa_key_file()
        proto.output_path = NamedTemporaryFile().name

        self.csr = CertificateSigningRequestBuilder.from_csr(proto)

    @staticmethod
    def create_rsa_key_file():
        """
        Helper function for creating RSA key files
        """
        key_path = NamedTemporaryFile().name
        private_key = TestSigningKey.create_rsa_key()
        TestSigningKey.write_key(key_path, private_key)

        return key_path

    def test_valid_csr(self):
        """
        Test that a Certificate Signing Request implements base functions
        """

        self.assertIsInstance(self.csr, _CertificateSigningRequest)

        for attribute in TestSubject.config["attributes"]:
            self.assertEqual(
                self.csr.get_attribute_for_oid(
                    ObjectIdentifier.from_string(attribute["oid"])
                ),
                b64decode(attribute["b64_value"].encode()),
                "Attributes should match config flie",
            )

    def test_export(self):
        """
        Test exporting of a certificate signing request
        """

        out_file = NamedTemporaryFile().name
        self.csr.export(out_file)

        with open(out_file, "rb") as csr_file:
            self.assertEqual(
                csr_file.read(),
                self.csr.public_bytes(serialization.Encoding.PEM),
                "Exported value should match PEM encoding",
            )


class TestMyBackend(TestCase):
    """
    Tests for x509 SSL Backend wrapper
    """

    def setUp(self):
        csr = load_csr(TestSubject.config)
        csr.key_path = TestCertificateSigningRequest.create_rsa_key_file()

        builder = x509.CertificateSigningRequestBuilder()
        self.builder = builder.subject_name(Subject.from_subject(csr.subject))

        self.signing_key = SigningKey.from_path(csr.key_path, csr.hash_type)
        self.backend = MyBackend()

    def test_create_x509_csr(self):
        """
        Test create x509 csr results in an instance of CertificateSigningRequest wrapper
        """

        csr = self.backend.create_x509_csr(
            builder=self.builder,
            private_key=self.signing_key.private_key,
            algorithm=self.signing_key.algorithm,
        )

        self.assertIsInstance(
            self.backend, Backend, "MyBackend should be a wrapper of OpenSSL Backend"
        )
        self.assertIsInstance(
            csr,
            CertificateSigningRequest,
            "Backend wrapper should generate an instance of wrapped CertificateSigningRequest",
        )


class TestCertificateSigningRequestBuilder(TestCase):
    """
    Tests for building Certificate Signing Requests from a config file
    """

    def test_from_csr(self):
        """
        Test creation of a Certificate Signing Request from config
        """

        proto = load_csr(TestSubject.config)
        proto.key_path = TestCertificateSigningRequest.create_rsa_key_file()

        csr = CertificateSigningRequestBuilder.from_csr(proto)

        self.assertIsInstance(
            csr,
            CertificateSigningRequest,
            "Builder should create wrapped CertificateSigningRequests",
        )
