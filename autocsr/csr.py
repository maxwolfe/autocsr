"""
Build Certificate Signing Requests
"""

from __future__ import annotations

from base64 import b64decode
from dataclasses import InitVar, dataclass
from functools import partial
from typing import Dict, Optional, Union

from cryptography import x509
from cryptography.hazmat._types import _PRIVATE_KEY_TYPES
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.backends.openssl.x509 import _CertificateSigningRequest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

import autocsr.protos.csr_pb2 as proto

PrivateKey = Union[
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
]
CsrSubject = proto.CertificateSigningRequest.Subject
HashType = proto.CertificateSigningRequest.HashType


class Attribute(x509.NameAttribute):
    """
    An x509 attribute created from configs
    """

    @classmethod
    def from_field(cls, field: str, value: str):
        """
        Create an attribute from each field of subject info
        """

        return cls(getattr(NameOID, field.upper()), value)


class Subject(x509.Name):
    """
    An x509 name object created from configs
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

    @classmethod
    def from_subject(cls, subject: CsrSubject):
        """
        Build a x509 name object from dictionary
        """

        attributes = []

        for field in cls.subject_fields:
            value = getattr(subject, field)

            if value:
                attributes.append(Attribute.from_field(field, value))

        return cls(attributes)


@dataclass
class SigningKey:
    """
    A signing key created from a config
    """

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

    def __post_init__(
        self,
        hash_type: HashType,
        approved_hashes: Dict[HashType, hashes.HashAlgorithm],
    ):
        """
        Map HashType enums to hash algorithms
        """

        self.algorithm = approved_hashes[hash_type]()

    @classmethod
    def from_path(cls, key_path: str, hash_type: HashType):
        """
        Build a Signing Key from key type and file path
        """

        with open(key_path, "rb") as key_file:
            return cls(
                private_key=serialization.load_pem_private_key(
                    key_file.read(), password=None
                ),
                hash_type=hash_type,
            )


class CertificateSigningRequest(_CertificateSigningRequest):
    """
    A custom certificate signing request
    """

    def __repr__(self):
        return (
            f"Subject: {self.subject}\n"
            f"Signature Algorithm: {self.signature_algorithm_oid}\n"
            f"Extensions: {self.extensions}\n"
            f"Valid Signature: {self.is_signature_valid}"
        )

    def export(self, filename: str):
        """
        Export CSR to a file
        """

        with open(filename, "wb") as output_file:
            output_file.write(self.public_bytes(Encoding.PEM))


class MyBackend(Backend):
    """
    A custom backend to override Certificate Signing Request building
    """

    def create_x509_csr(
        self,
        builder: x509.CertificateSigningRequestBuilder,
        private_key: _PRIVATE_KEY_TYPES,
        algorithm: Optional[hashes.HashAlgorithm],
    ) -> _CertificateSigningRequest:
        """
        Create custom Certificate Signing Requests
        """

        csr = super().create_x509_csr(builder, private_key, algorithm)

        return CertificateSigningRequest(backend=self, x509_req=csr._x509_req)


class CertificateSigningRequestBuilder:
    """
    An x509 certificate signing request created from configs
    """

    @staticmethod
    def from_csr(csr: proto.CertificateSigningRequest):
        """
        Build an x509 Certificate Signing Request Object from a config
        """

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(Subject.from_subject(csr.subject))

        for attribute in csr.attributes:
            builder = builder.add_attribute(
                oid=x509.ObjectIdentifier(attribute.oid),
                value=b64decode(attribute.b64_value.encode()),
            )

        key = SigningKey.from_path(csr.key_path, csr.hash_type)

        return builder.sign(
            private_key=key.private_key,
            algorithm=key.algorithm,
            backend=MyBackend(),
        )
