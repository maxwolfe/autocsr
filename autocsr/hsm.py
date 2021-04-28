"""Implementations for supported HSMs."""

from __future__ import annotations

import abc
from dataclasses import InitVar, dataclass
from typing import Dict, Union

import pkcs11
from Crypto.PublicKey import DSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from pkcs11.util.dsa import encode_dsa_signature
from pkcs11.util.ec import encode_ec_public_key, encode_ecdsa_signature
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
        """
        Convert a `pkcs11` public key to a `cryptography` public key.

        :param pkcs11.KeyType pkcs11_public_key: A `pkcs11` format public key.
        :return: A `cryptography` format public key.
        :rtype: :class:`PublicKey`
        """
        if self.pkcs11_key_type == pkcs11.KeyType.RSA:
            der_public_key = encode_rsa_public_key(pkcs11_public_key)
        elif self.pkcs11_key_type == pkcs11.KeyType.DSA:
            y = int.from_bytes(
                pkcs11_public_key[pkcs11.Attribute.VALUE], byteorder="big"
            )
            g = int.from_bytes(
                pkcs11_public_key[pkcs11.Attribute.BASE], byteorder="big"
            )
            p = int.from_bytes(
                pkcs11_public_key[pkcs11.Attribute.PRIME], byteorder="big"
            )
            q = int.from_bytes(
                pkcs11_public_key[pkcs11.Attribute.SUBPRIME], byteorder="big"
            )

            der_public_key = DSA.construct((y, g, p, q)).export_key(format="DER")
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

    token_label: str
    key_label: str
    user_pin: str
    so_file: str
    types: InitVar[Dict[KeyType, pkcs11.KeyType]] = {
        KeyType.RSA: pkcs11.KeyType.RSA,
        KeyType.DSA: pkcs11.KeyType.DSA,
        KeyType.EC: pkcs11.KeyType.EC,
    }
    approved_hashes: InitVar[
        Dict[KeyType, Dict[HashType, Union[hashes.HashAlgorithm, pkcs11.Mechanism]]]
    ] = {
        KeyType.RSA: {
            HashType.SHA224: pkcs11.Mechanism.SHA224_RSA_PKCS,
            HashType.SHA256: pkcs11.Mechanism.SHA256_RSA_PKCS,
            HashType.SHA384: pkcs11.Mechanism.SHA384_RSA_PKCS,
            HashType.SHA512: pkcs11.Mechanism.SHA512_RSA_PKCS,
        },
        KeyType.DSA: {
            HashType.SHA256: pkcs11.Mechanism.DSA_SHA256,
            HashType.SHA224: pkcs11.Mechanism.DSA_SHA224,
        },
        KeyType.EC: {
            HashType.SHA224: hashes.SHA224,
            HashType.SHA256: hashes.SHA256,
            HashType.SHA384: hashes.SHA384,
            HashType.SHA512: hashes.SHA512,
        },
    }

    def __post_init__(
        self,
        types: Dict[KeyType, pkcs11.KeyType],
        approved_hashes: Dict[
            KeyType, Dict[HashType, Union[hashes.HashAlgorithm, pkcs11.Mechanism]]
        ],
    ):
        """Load token for SoftHSM operations."""
        lib = pkcs11.lib(self.so_file)
        self.token = lib.get_token(token_label=self.token_label)

        self.pkcs11_key_type = types[self.key_type]
        self.pkcs11_hash_type = approved_hashes[self.key_type][self.hash_type]

    @property
    def public_key(self) -> PublicKey:
        """
        Get the public key from SoftHSM.

        :return: A public key stored in SoftHSM.
        :rtype: :class:`PublicKey`
        """
        with self.token.open(user_pin=self.user_pin) as session:
            public_key = session.get_key(
                label=self.key_label,
                key_type=self.pkcs11_key_type,
                object_class=pkcs11.ObjectClass.PUBLIC_KEY,
            )

            return self.pkcs11_to_crypto_key(public_key)

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with a key from SoftHSM.

        :param bytes message: The data to sign.
        :return: The signed data using a private key in SoftHSM.
        :rtype: bytes
        """
        with self.token.open(rw=True, user_pin=self.user_pin) as session:
            private_key = session.get_key(
                label=self.key_label,
                key_type=self.pkcs11_key_type,
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
            )

            if self.key_type == KeyType.EC:
                digest = hashes.Hash(self.pkcs11_hash_type())
                digest.update(message)
                signature = private_key.sign(
                    digest.finalize(), mechanism=pkcs11.Mechanism.ECDSA
                )
                return encode_ecdsa_signature(signature)

            signature = private_key.sign(message, mechanism=self.pkcs11_hash_type)

            if self.key_type == KeyType.RSA:
                return signature

            if self.key_type == KeyType.DSA:
                return encode_dsa_signature(signature)

    @classmethod
    def from_proto(cls, hsm_info: HsmInfo, hash_type: HashType):
        """
        Create a :class:`SoftHsm` instance from a protobuf.

        :param HsmInfo hsm_info: A protobuf representation of HSM details.
        :param HashType hash_type: A protobuf representation of signing information.
        :return: A structure for interacting with keys in SoftHSM.
        :rtype: :class:`SoftHsm`
        """
        softhsm = hsm_info.softhsm

        return cls(
            hash_type=hash_type,
            key_type=hsm_info.key_type,
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
        """
        Create an HSM instance from hsm_info protobuf.

        :param HsmInfo hsm_info: A protobuf representation of HSM details.
        :param HashType hash_type: A protobuf representation of signing information.
        :return: A structure for interacting with keys in the selected HSM.
        :rtype: :class:`Hsm`
        """
        return HsmFactory.hsms.get(hsm_info.WhichOneof("hsm")).from_proto(
            hsm_info=hsm_info,
            hash_type=hash_type,
        )
