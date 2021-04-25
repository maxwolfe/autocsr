"""Unit tests for CSR creation objects."""

from base64 import b64decode
from tempfile import NamedTemporaryFile
from unittest import TestCase
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.backends.openssl.x509 import _CertificateSigningRequest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

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
KeyType = protos.CertificateSigningRequest.KeyType
SoftHsm = protos.CertificateSigningRequest.SoftHsm
HsmInfo = protos.CertificateSigningRequest.HsmInfo


class TestAttribute(TestCase):
    """Test creation of Attributes."""

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
        """Validate an attribute."""
        self.assertIsInstance(
            attribute,
            x509.NameAttribute,
            "Attribute must be an instance of x509 NameAttribute",
        )

    def test_from_field(self):
        """Test creation of an x509 attribute from a field and value."""
        for field in self.subject_fields:
            value = self.subject_dict.get(field)
            attribute = Attribute.from_field(field, value)

            self.validate_attribute(attribute)


class TestSubject(TestCase):
    """Test creation of Subject object."""

    config = {
        "subject": TestAttribute.subject_dict,
        "key_info": {
            "key_path": "/tmp/create_test.key",
            "create": True,
        },
        "output_path": "./fixtures/test.csr",
        "hash_type": "SHA256",
        "attributes": [
            {"oid": "2.5.29.17", "b64_value": "dGVzdA=="},
            {"oid": "issuerAltName", "b64_value": "aGk="},
        ],
        "extensions": [
            {"extension_type": "OCSPNoCheck"},
            {"subject_key_identifier": {"b64_digest": "dGVzdCBiNjQgZGlnZXN0"}},
            {"basic_constraints": {"ca": True, "path_length": 123}},
            {"policy_constraints": {"require_explicit_policy": 123}},
        ],
    }

    def setUp(self):
        """Set up for a Subject."""
        self.proto = load_csr(self.config)

    def validate_subject(self, subject: Subject):
        """Validate an x509 Name."""
        self.assertIsInstance(
            subject,
            x509.Name,
            "Attribute must be an instance of x509 NameAttribute",
        )

    def test_from_proto(self):
        """Test creation of an x509.Name from a config file."""
        subject = Subject.from_proto(self.proto.subject)

        self.validate_subject(subject)


class TestSigningKey(TestCase):
    """Tests for creating a Signing Key from a config file."""

    def setUp(self):
        """Set up a SigningKey."""
        self.proto = protos.CertificateSigningRequest()

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
        """Generate RSA keys."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    @staticmethod
    def write_key(key_path: str, private_key: PrivateKey):
        """Write a private key to a temporary file."""
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
        """Validate signing key objects."""
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

    def test_create_key(self):
        """Test correct key creation for signing keys."""
        self.proto.key_info.create = True

        for hash_type in self.approved_hashes:
            self.proto.key_info.key_path = self.rsa_key_path
            self.proto.key_info.key_type = KeyType.RSA
            rsa_signing_key = SigningKey.from_key_info(self.proto.key_info, hash_type)
            rsa_private_key = serialization.load_pem_private_key(
                open(self.rsa_key_path, "rb").read(),
                password=None,
            )
            self.validate_signing_key(rsa_signing_key, rsa_private_key, hash_type)

            self.proto.key_info.key_path = self.dsa_key_path
            self.proto.key_info.key_type = KeyType.DSA
            dsa_signing_key = SigningKey.from_key_info(self.proto.key_info, hash_type)
            dsa_private_key = serialization.load_pem_private_key(
                open(self.dsa_key_path, "rb").read(),
                password=None,
            )
            self.validate_signing_key(dsa_signing_key, dsa_private_key, hash_type)

            self.proto.key_info.key_path = self.ec_key_path
            self.proto.key_info.key_type = KeyType.EC
            ec_signing_key = SigningKey.from_key_info(self.proto.key_info, hash_type)
            ec_private_key = serialization.load_pem_private_key(
                open(self.ec_key_path, "rb").read(),
                password=None,
            )
            self.validate_signing_key(ec_signing_key, ec_private_key, hash_type)

    def test_from_hsm_info(self):
        """Test the creation of a dummy SigningKey from hsm info."""
        softhsm = SoftHsm()
        softhsm.token_label = "test_token_label"
        softhsm.key_label = "test_key_label"
        softhsm.user_pin = "test_user_pin"
        softhsm.so_file = "test_so_file"

        hsm_info = HsmInfo()
        hsm_info.softhsm.CopyFrom(softhsm)

        hash_type = HashType.SHA256

        hsm_info.key_type = KeyType.RSA
        dummy_rsa_key = SigningKey.from_hsm_info(hsm_info, hash_type)
        self.assertIsInstance(
            dummy_rsa_key.private_key,
            rsa.RSAPrivateKey,
            "Dummy key should be an RSA Key",
        )

        hsm_info.key_type = KeyType.DSA
        dummy_dsa_key = SigningKey.from_hsm_info(hsm_info, hash_type)
        self.assertIsInstance(
            dummy_dsa_key.private_key,
            dsa.DSAPrivateKey,
            "Dummy key should be a DSA Key",
        )

        hsm_info.key_type = KeyType.EC
        dummy_ec_key = SigningKey.from_hsm_info(hsm_info, hash_type)
        self.assertIsInstance(
            dummy_ec_key.private_key,
            ec.EllipticCurvePrivateKey,
            "Dummy key should be an EC Key",
        )

    def test_from_key_info(self):
        """Test the creation of a SigningKey from key info."""
        for hash_type in self.approved_hashes:
            self.proto.key_info.key_path = self.rsa_key_path
            rsa_signing_key = SigningKey.from_key_info(self.proto.key_info, hash_type)

            self.proto.key_info.key_path = self.dsa_key_path
            dsa_signing_key = SigningKey.from_key_info(self.proto.key_info, hash_type)

            self.proto.key_info.key_path = self.ec_key_path
            ec_signing_key = SigningKey.from_key_info(self.proto.key_info, hash_type)

            self.validate_signing_key(rsa_signing_key, self.rsa_private_key, hash_type)
            self.validate_signing_key(dsa_signing_key, self.dsa_private_key, hash_type)
            self.validate_signing_key(ec_signing_key, self.ec_private_key, hash_type)

    def test_from_path(self):
        """Test the creation of a SigningKey from a key file."""
        for hash_type in self.approved_hashes:
            rsa_signing_key = SigningKey._from_path(self.rsa_key_path, hash_type)
            dsa_signing_key = SigningKey._from_path(self.dsa_key_path, hash_type)
            ec_signing_key = SigningKey._from_path(self.ec_key_path, hash_type)

            self.validate_signing_key(rsa_signing_key, self.rsa_private_key, hash_type)
            self.validate_signing_key(dsa_signing_key, self.dsa_private_key, hash_type)
            self.validate_signing_key(ec_signing_key, self.ec_private_key, hash_type)


class TestCertificateSigningRequest(TestCase):
    """Tests for x509 CertificateSigningRequest wrapper."""

    def setUp(self):
        """Set up a CertificateSigningRequest."""
        proto = load_csr(TestSubject.config)
        proto.output_path = NamedTemporaryFile().name

        proto.key_info.key_type = KeyType.RSA
        self.rsa_csr = CertificateSigningRequestBuilder.from_proto(proto)
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )

        proto.key_info.key_type = KeyType.DSA
        self.dsa_csr = CertificateSigningRequestBuilder.from_proto(proto)
        self.dsa_private_key = dsa.generate_private_key(
            key_size=2048,
        )

        proto.key_info.key_type = KeyType.EC
        self.ec_csr = CertificateSigningRequestBuilder.from_proto(proto)
        self.ec_private_key = ec.generate_private_key(
            ec.SECP256R1(),
        )

    @staticmethod
    def create_rsa_key_file():
        """Create RSA key files."""
        key_path = NamedTemporaryFile().name
        private_key = TestSigningKey.create_rsa_key()
        TestSigningKey.write_key(key_path, private_key)

        return key_path

    def test_valid_csr(self):
        """Test that a Certificate Signing Request implements base class."""
        self.assertIsInstance(self.rsa_csr, _CertificateSigningRequest)

        for attribute in TestSubject.config["attributes"]:
            self.assertEqual(
                self.rsa_csr.get_attribute_for_oid(
                    ObjectIdentifier.from_string(attribute["oid"])
                ),
                b64decode(attribute["b64_value"].encode()),
                "Attributes should match config flie",
            )

    def test_set_pubkey(self):
        """Test updating a public key in a CSR."""
        self.assertTrue(self.rsa_csr.is_signature_valid, "CSR should be valid")
        self.rsa_csr.set_pubkey(self.rsa_private_key.public_key())
        self.assertFalse(
            self.rsa_csr.is_signature_valid,
            "CSR should no longer be valid after public key swap",
        )
        self.assertEqual(
            self.rsa_csr.public_key().public_numbers(),
            self.rsa_private_key.public_key().public_numbers(),
            "Public key of swapped key should match key in CSR",
        )

        self.assertTrue(self.dsa_csr.is_signature_valid, "CSR should be valid")
        self.dsa_csr.set_pubkey(self.dsa_private_key.public_key())
        self.assertFalse(
            self.dsa_csr.is_signature_valid,
            "CSR should no longer be valid after public key swap",
        )
        self.assertEqual(
            self.dsa_csr.public_key().public_numbers(),
            self.dsa_private_key.public_key().public_numbers(),
            "Public key of swapped key should match key in CSR",
        )

        self.assertTrue(self.ec_csr.is_signature_valid, "CSR should be valid")
        self.ec_csr.set_pubkey(self.ec_private_key.public_key())
        self.assertFalse(
            self.ec_csr.is_signature_valid,
            "CSR should no longer be valid after public key swap",
        )
        self.assertEqual(
            self.ec_csr.public_key().public_numbers(),
            self.ec_private_key.public_key().public_numbers(),
            "Public key of swapped key should match key in CSR",
        )

    def test_set_signature(self):
        """Test updating a signature in a CSR."""
        message = b"test"

        rsa_signature = self.rsa_private_key.sign(
            message, padding.PKCS1v15(), hashes.SHA256()
        )
        dsa_signature = self.dsa_private_key.sign(message, hashes.SHA256())
        ec_signature = self.ec_private_key.sign(message, ec.ECDSA(hashes.SHA256()))

        self.assertTrue(self.rsa_csr.is_signature_valid, "CSR should be valid")
        self.rsa_csr.set_signature(rsa_signature)
        self.assertFalse(
            self.rsa_csr.is_signature_valid,
            "CSR should no longer be valid after signature swap",
        )
        self.assertEqual(
            self.rsa_csr.signature,
            rsa_signature,
            "Signature of CSR should match swapped signature",
        )

        self.assertTrue(self.dsa_csr.is_signature_valid, "CSR should be valid")
        self.dsa_csr.set_signature(dsa_signature)
        self.assertFalse(
            self.dsa_csr.is_signature_valid,
            "CSR should no longer be valid after signature swap",
        )
        self.assertEqual(
            self.dsa_csr.signature,
            dsa_signature,
            "Signature of CSR should match swapped signature",
        )

        self.assertTrue(self.ec_csr.is_signature_valid, "CSR should be valid")
        self.ec_csr.set_signature(ec_signature)
        self.assertFalse(
            self.ec_csr.is_signature_valid,
            "CSR should no longer be valid after signature swap",
        )
        self.assertEqual(
            self.ec_csr.signature,
            ec_signature,
            "Signature of CSR should match swapped signature",
        )

    def test_export(self):
        """Test exporting of a certificate signing request."""
        out_file = NamedTemporaryFile().name
        self.rsa_csr.export(out_file)

        with open(out_file, "rb") as csr_file:
            self.assertEqual(
                csr_file.read(),
                self.rsa_csr.public_bytes(serialization.Encoding.PEM),
                "Exported value should match PEM encoding",
            )


class TestMyBackend(TestCase):
    """Tests for x509 SSL Backend wrapper."""

    def setUp(self):
        """Set up a backend."""
        csr = load_csr(TestSubject.config)
        csr.key_info.key_path = TestCertificateSigningRequest.create_rsa_key_file()

        builder = x509.CertificateSigningRequestBuilder()
        self.builder = builder.subject_name(Subject.from_proto(csr.subject))

        self.signing_key = SigningKey._from_path(csr.key_info.key_path, csr.hash_type)
        self.backend = MyBackend()

    def test_create_x509_csr(self):
        """
        Test create x509 csr.

        Test create x509 csr results in an instance of
        CertificateSigningRequest wrapper.
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
    """Tests for building Certificate Signing Requests from a config file."""

    def setUp(self):
        """Set up CertificateSigningRequestBuilder."""
        self.proto = load_csr(TestSubject.config)
        self.proto.key_info.key_path = (
            TestCertificateSigningRequest.create_rsa_key_file()
        )
        self.builder = x509.CertificateSigningRequestBuilder()
        self.builder = self.builder.subject_name(Subject.from_proto(self.proto.subject))

    def test_from_proto(self):
        """Test creation of a Certificate Signing Request from config."""
        csr = CertificateSigningRequestBuilder.from_proto(self.proto)

        self.assertIsInstance(
            csr,
            CertificateSigningRequest,
            "Builder should create wrapped CertificateSigningRequests",
        )

    def test_sign_with_key_info(self):
        """Test signing from key info proto."""
        csr = CertificateSigningRequestBuilder._sign_with_key_info(
            self.proto, self.builder
        )

        self.assertIsInstance(
            csr,
            CertificateSigningRequest,
            "Builder should create wrapped CertificateSigningRequests",
        )

    @patch.object(CertificateSigningRequest, "set_signature")
    @patch.object(CertificateSigningRequest, "set_pubkey")
    @patch("autocsr.hsm.HsmFactory")
    def test_sign_with_hsm_info(
        self,
        mock_hsm_factory,
        mock_set_pubkey,
        mock_set_signature,
    ):
        """Test signing from hsm info proto."""
        softhsm = SoftHsm()
        softhsm.token_label = "test_token_label"
        softhsm.key_label = "test_key_label"
        softhsm.user_pin = "test_user_pin"
        softhsm.so_file = "test_so_file"

        hsm_info = HsmInfo()
        hsm_info.softhsm.CopyFrom(softhsm)
        hsm_info.key_type = KeyType.RSA

        self.proto.hsm_info.CopyFrom(hsm_info)

        csr = CertificateSigningRequestBuilder._sign_with_hsm_info(
            self.proto, self.builder
        )

        mock_set_pubkey.assert_called_once()
        mock_set_signature.assert_called_once()

        self.assertIsInstance(
            csr,
            CertificateSigningRequest,
            "Builder should create wrapped CertificateSigningRequests",
        )
