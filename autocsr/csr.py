"""
Build Certificate Signing Requests
"""

from dataclasses import dataclass
from typing import Optional, Union

from cryptography import x509
from cryptography.hazmat._types import _PRIVATE_KEY_TYPES
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.backends.openssl.x509 import _CertificateSigningRequest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

import autocsr.protos.csr_pb2 as proto

PrivateKey = Union[
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
]


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
    def from_subject(cls, subject: proto.CertificateSigningRequest.Subject):
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
    algorithm: HashAlgorithm

    @classmethod
    def from_path(cls, key_path: str):
        """
        Build a Signing Key from key type and file path
        """

        with open(key_path, "rb") as key_file:
            return cls(
                private_key=serialization.load_pem_private_key(
                    key_file.read(), password=None
                ),
                algorithm=SHA256(),
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
        algorithm: Optional[HashAlgorithm],
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

        key = SigningKey.from_path(csr.key_path)
        return builder.sign(
            private_key=key.private_key,
            algorithm=key.algorithm,
            backend=MyBackend(),
        )
