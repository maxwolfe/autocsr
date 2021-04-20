"""Build Certificate Signing Requests."""

from __future__ import annotations

from base64 import b64decode
from dataclasses import InitVar, dataclass
from functools import partial
from typing import ClassVar, Dict, Optional, Union

from cryptography import x509
from cryptography.hazmat._types import _PRIVATE_KEY_TYPES
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.backends.openssl.x509 import _CertificateSigningRequest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto as openssl
from pyasn1.codec.der.decoder import decode as asn1_decode
from pyasn1.codec.der.encoder import encode as asn1_encode
from pyasn1.type.univ import BitString
from pyasn1_modules.rfc2314 import CertificationRequest

import autocsr.protos.csr_pb2 as proto
from autocsr.extensions import Extension
from autocsr.hsm import HsmFactory
from autocsr.oid import ObjectIdentifier

PrivateKey = Union[
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
]
PublicKey = Union[
    rsa.RSAPublicKey,
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
]
CsrSubject = proto.CertificateSigningRequest.Subject
HashType = proto.CertificateSigningRequest.HashType
KeyType = proto.CertificateSigningRequest.KeyType
KeyInfo = proto.CertificateSigningRequest.KeyInfo
HsmInfo = proto.CertificateSigningRequest.HsmInfo
Curve = proto.CertificateSigningRequest.Curve
GenericKeyInfo = Union[KeyInfo, HsmInfo]


class Attribute(x509.NameAttribute):
    """An x509 attribute created from configs."""

    @classmethod
    def from_field(cls, field: str, value: str):
        """Create an attribute from each field of subject info."""
        return cls(getattr(NameOID, field.upper()), value)


class Subject(x509.Name):
    """An x509 name object created from configs."""

    subject_fields = [
        "common_name",
        "country_name",
        "state_or_province_name",
        "locality_name",
        "organization_name",
        "organizational_unit_name",
        "email_address",
    ]

    @classmethod
    def from_subject(cls, subject: CsrSubject):
        """Build a x509 name object from dictionary."""
        attributes = []

        for field in cls.subject_fields:
            value = getattr(subject, field)

            if value:
                attributes.append(Attribute.from_field(field, value))

        return cls(attributes)


@dataclass
class SigningKey:
    """A signing key created from a config."""

    private_key: PrivateKey
    algorithm: hashes.HashAlgorithm = None
    hash_type: InitVar[HashType] = None
    approved_hashes: InitVar[Dict[HashType, hashes.HashAlgorithm]] = {
        HashType.SHA256: hashes.SHA256,
        HashType.SHA224: hashes.SHA224,
        HashType.SHA384: hashes.SHA384,
        HashType.SHA512: hashes.SHA512,
        HashType.SHA512_224: hashes.SHA512_224,
        HashType.SHA512_256: hashes.SHA512_256,
        HashType.BLAKE2b: partial(hashes.BLAKE2b, digest_size=64),
        HashType.BLAKE2s: partial(hashes.BLAKE2s, digest_size=32),
        HashType.SHA3_224: hashes.SHA3_224,
        HashType.SHA3_256: hashes.SHA3_256,
        HashType.SHA3_384: hashes.SHA3_384,
        HashType.SHA3_512: hashes.SHA3_512,
    }
    CURVES: ClassVar[Dict[Curve, ec.EllipticCurve]] = {
        Curve.SECP256R1: ec.SECP256R1,
        Curve.SECP384R1: ec.SECP384R1,
        Curve.SECP521R1: ec.SECP521R1,
        Curve.SECP192R1: ec.SECP192R1,
        Curve.SECP256K1: ec.SECP256K1,
        Curve.BrainpoolP256R1: ec.BrainpoolP256R1,
        Curve.BrainpoolP384R1: ec.BrainpoolP384R1,
        Curve.BrainpoolP512R1: ec.BrainpoolP512R1,
        Curve.SECT571K1: ec.SECT571K1,
        Curve.SECT409K1: ec.SECT409K1,
        Curve.SECT283K1: ec.SECT283K1,
        Curve.SECT233K1: ec.SECT233K1,
        Curve.SECT163K1: ec.SECT163K1,
        Curve.SECT571R1: ec.SECT571R1,
        Curve.SECT409R1: ec.SECT409R1,
        Curve.SECT283R1: ec.SECT283R1,
        Curve.SECT233R1: ec.SECT233R1,
        Curve.SECT163R2: ec.SECT163R2,
    }

    def __post_init__(
        self,
        hash_type: HashType,
        approved_hashes: Dict[HashType, hashes.HashAlgorithm],
    ):
        """Map HashType enums to hash algorithms."""
        self.algorithm = approved_hashes[hash_type]()

    @staticmethod
    def create_rsa_key(key_info: GenericKeyInfo) -> rsa.RSAPrivateKey:
        """Create an RSA Private Key from a key info structure."""
        if not key_info.key_size:
            key_info.key_size = 2048

        if not key_info.public_exponent:
            key_info.public_exponent = 65537

        return rsa.generate_private_key(
            public_exponent=key_info.public_exponent,
            key_size=key_info.key_size,
        )

    @staticmethod
    def create_dsa_key(key_info: GenericKeyInfo) -> dsa.DSAPrivateKey:
        """Create a DSA Private Key from a key info structure."""
        if not key_info.key_size:
            key_info.key_size = 2048

        return dsa.generate_private_key(
            key_size=key_info.key_size,
        )

    @staticmethod
    def create_ec_key(key_info: GenericKeyInfo) -> ec.EllipticCurvePrivateKey:
        """Create an EC Private Key from a key info structure."""
        return ec.generate_private_key(
            curve=SigningKey.CURVES[key_info.curve](),
        )

    @staticmethod
    def create_key(key_info: KeyInfo) -> PrivateKey:
        """Create and export a private key from a key info object."""
        if key_info.key_type == KeyType.RSA:
            private_key = SigningKey.create_rsa_key(key_info)
        elif key_info.key_type == KeyType.DSA:
            private_key = SigningKey.create_dsa_key(key_info)
        elif key_info.key_type == KeyType.EC:
            private_key = SigningKey.create_ec_key(key_info)
        else:
            raise TypeError(f"Key type: {key_info.key_type} does not exist")

        with open(key_info.key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        return private_key

    @classmethod
    def from_path(cls, key_path: str, hash_type: HashType):
        """Build a Signing Key from key type and file path."""
        with open(key_path, "rb") as key_file:
            return cls(
                private_key=serialization.load_pem_private_key(
                    key_file.read(), password=None
                ),
                hash_type=hash_type,
            )

    @classmethod
    def from_key_info(cls, key_info: KeyInfo, hash_type: HashType):
        """Build a Signing Key from key information structure."""
        if key_info.create:
            return cls(
                private_key=cls.create_key(key_info),
                hash_type=hash_type,
            )

        return cls.from_path(
            key_path=key_info.key_path,
            hash_type=hash_type,
        )

    @classmethod
    def from_hsm_info(cls, hsm_info: HsmInfo, hash_type: HashType):
        """Build a Dummy Signing Key from hsm information structure."""
        if hsm_info.key_type == KeyType.RSA:
            return cls(SigningKey.create_rsa_key(hsm_info), hash_type=hash_type)

        if hsm_info.key_type == KeyType.DSA:
            return cls(SigningKey.create_dsa_key(hsm_info), hash_type=hash_type)

        if hsm_info.key_type == KeyType.EC:
            return cls(SigningKey.create_ec_key(hsm_info), hash_type=hash_type)

        raise TypeError(f"Key type: {hsm_info.key_type} does not exist")


class CertificateSigningRequest(_CertificateSigningRequest):
    """A custom certificate signing request."""

    def __repr__(self):
        """Debug representation of a CSR."""
        return (
            f"Subject: {self.subject}\n"
            f"Signature Algorithm: {self.signature_algorithm_oid}\n"
            f"Extensions: {self.extensions}\n"
            f"Valid Signature: {self.is_signature_valid}"
        )

    def set_pubkey(self, public_key: PublicKey):
        """Modify the public key of a CSR."""
        openssl_req = openssl.X509Req.from_cryptography(self)

        key_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        openssl_key = openssl.load_publickey(openssl.FILETYPE_PEM, key_pem)

        openssl_req.set_pubkey(openssl_key)

        self._x509_req = openssl_req.to_cryptography()._x509_req

    def set_signature(self, signature: bytes):
        """Return a new CSR with modified signature."""
        der_csr = self.public_bytes(serialization.Encoding.DER)
        asn1_csr, _ = asn1_decode(
            der_csr,
            asn1Spec=CertificationRequest(),
        )

        asn1_csr.setComponentByName("signature", BitString.fromOctetString(signature))

        self._x509_req = x509.load_der_x509_csr(asn1_encode(asn1_csr))._x509_req

    def export(self, filename: str):
        """Export CSR to a file."""
        with open(filename, "wb") as output_file:
            output_file.write(self.public_bytes(serialization.Encoding.PEM))


class MyBackend(Backend):
    """A custom backend to override Certificate Signing Request building."""

    def create_x509_csr(
        self,
        builder: x509.CertificateSigningRequestBuilder,
        private_key: _PRIVATE_KEY_TYPES,
        algorithm: Optional[hashes.HashAlgorithm],
    ) -> _CertificateSigningRequest:
        """Create custom Certificate Signing Requests."""
        csr = super().create_x509_csr(builder, private_key, algorithm)

        return CertificateSigningRequest(backend=self, x509_req=csr._x509_req)


class CertificateSigningRequestBuilder:
    """An x509 certificate signing request created from configs."""

    @staticmethod
    def sign_with_key_info(
        csr: proto.CertificateSigningRequest,
        builder: x509.CertificateSigningRequestBuilder,
    ):
        """Sign a CertificateSigningRequest with filesystem key."""
        key = SigningKey.from_key_info(csr.key_info, csr.hash_type)

        return builder.sign(
            private_key=key.private_key,
            algorithm=key.algorithm,
            backend=MyBackend(),
        )

    @staticmethod
    def sign_with_hsm_info(
        csr: proto.CertificateSigningRequest,
        builder: x509.CertificateSigningRequestBuilder,
    ):
        """Sign a CertificateSigningRequest with key information in an HSM."""
        hsm = HsmFactory.from_hsm_info(csr.hsm_info, csr.hash_type)

        dummy_key = SigningKey.from_hsm_info(csr.hsm_info, csr.hash_type)

        base_csr = builder.sign(
            private_key=dummy_key.private_key,
            algorithm=dummy_key.algorithm,
            backend=MyBackend(),
        )

        base_csr.set_pubkey(hsm.public_key)
        base_csr.set_signature(hsm.sign(base_csr.tbs_certrequest_bytes))

        return base_csr

    @staticmethod
    def from_csr(csr: proto.CertificateSigningRequest):
        """Build an x509 Certificate Signing Request Object from a config."""
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(Subject.from_subject(csr.subject))

        for attribute in csr.attributes:
            builder = builder.add_attribute(
                oid=ObjectIdentifier.from_string(attribute.oid),
                value=b64decode(attribute.b64_value.encode()),
            )

        for extension in csr.extensions:
            builder = builder.add_extension(
                extval=Extension.from_proto(extension),
                critical=extension.critical,
            )

        if csr.WhichOneof("key") == "key_info":
            return CertificateSigningRequestBuilder.sign_with_key_info(csr, builder)
        elif csr.WhichOneof("key") == "hsm_info":
            return CertificateSigningRequestBuilder.sign_with_hsm_info(csr, builder)
        else:
            raise TypeError("Neither filesystem key nor HSM key selected")
