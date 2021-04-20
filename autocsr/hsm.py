"""Implementations for supported HSMs."""

import abc
from dataclasses import InitVar, dataclass
from typing import Union, Dict

import pkcs11
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from pkcs11.util.dsa import encode_dsa_public_key
from pkcs11.util.ec import encode_ec_public_key
from pkcs11.util.rsa import encode_rsa_public_key

import autocsr.protos.csr_pb2 as proto

PublicKey = Union[
    rsa.RSAPublicKey,
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
]
HsmInfo = proto.CertificateSigningRequest.HsmInfo
KeyType = proto.CertificateSigningRequest.KeyType
HashType = proto.CertificateSigningRequest.HashType


@dataclass
class Hsm(abc.ABC):
    """Abstract class for HSMs."""

    hash_type: HashType
    key_type: KeyType

    @property
    @abc.abstractmethod
    def public_key(self) -> PublicKey:
        """Get the public key from the HSM."""

    @abc.abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Sign a message with a predefined key from the HSM."""

    def pkcs11_to_crypto_key(self, pkcs11_public_key: pkcs11.KeyType) -> PublicKey:
        """Convert a pkcs11 public key to a cryptography public key."""
        if self.pkcs11_key_type == pkcs11.KeyType.RSA:
            der_public_key = encode_rsa_public_key(pkcs11_public_key)
        elif self.pkcs11_key_type == pkcs11.KeyType.DSA:
            der_public_key = encode_dsa_public_key(pkcs11_public_key)
        elif self.pkcs11_key_type == pkcs11.KeyType.EC:
            der_public_key = encode_ec_public_key(pkcs11_public_key)
        else:
            raise TypeError(f"Key type for {pkcs11_public_key} not supported")

        return load_der_public_key(der_public_key)

    @classmethod
    @abc.abstractmethod
    def from_proto(cls, hsm_info: HsmInfo, hash_info: HashType):
        """Create an HSM instance from a protobuf."""


@dataclass
class SoftHsm(Hsm):
    """An implementation of SoftHsm for signing."""

    slot_number: int
    token_label: str
    key_label: str
    user_pin: str
    so_file: str

    def __post_init__(self):
        """Load token for SoftHSM operations."""
        lib = pkcs11.lib(self.so_file)
        self.token = lib.get_token(token_label=self.token_label)
        types = {
            KeyType.RSA: pkcs11.KeyType.RSA,
            KeyType.DSA: pkcs11.KeyType.DSA,
            KeyType.EC: pkcs11.KeyType.EC,
        }
        self.pkcs11_key_type = types.get(self.key_type)

    @property
    def public_key(self) -> PublicKey:
        """Get the public key from SoftHSM."""
        with self.token.open(user_pin=self.user_pin) as session:
            public_key = session.get_key(
                label=self.key_label,
                key_type=self.pkcs11_key_type,
                object_class=pkcs11.ObjectClass.PUBLIC_KEY,
            )

            return self.pkcs11_to_crypto_key(public_key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message with a key from SoftHSM."""
        with self.token.open(rw=True, user_pin=self.user_pin) as session:
            private_key = session.get_key(
                label=self.key_label,
                key_type=self.pkcs11_key_type,
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
            )

            return private_key.sign(message)

    @classmethod
    def from_proto(cls, hsm_info: HsmInfo, hash_type: HashType):
        """Create a SoftHSM instance from a protobuf."""
        softhsm = hsm_info.softhsm

        return cls(
            hash_type=hash_type,
            key_type=hsm_info.key_type,
            slot_number=softhsm.slot_number,
            token_label=softhsm.token_label,
            key_label=softhsm.key_label,
            user_pin=softhsm.user_pin,
            so_file=softhsm.so_file,
        )


class HsmFactory:
    """Create HSMs from HSMInfo configs."""

    hsms = {
        "softhsm": SoftHsm,
    }

    @staticmethod
    def from_hsm_info(hsm_info: HsmInfo, hash_type: HashType):
        """Create an HSM instance from hsm_info protobuf."""
        return HsmFactory.hsms.get(hsm_info.WhichOneof("hsm")).from_proto(
            hsm_info=hsm_info,
            hash_type=hash_type,
        )
