"""
Implementations for supported HSMs
"""

import abc
from dataclasses import dataclass

import autocsr.protos.csr_pb2 as proto

HsmInfo = proto.CertificateSigningRequest.HsmInfo
HsmType = proto.CertificateSigningRequest.HsmType
HashType = proto.CertificateSigningRequest.HashType


@dataclass
class Hsm(abc.ABC):
    """
    Abstract class for HSMs
    """

    uri: str
    hash_type: HashType

    @abc.abstractproperty
    def public_key(self):
        """
        Get the public key from the HSM
        """

    @abc.abstractmethod
    def sign(self, message: bytes):
        """
        Sign a message with a predefined key from the HSM
        """


class SoftHsm(Hsm):
    """
    An implementation of SoftHsm for signing
    """

    @property
    def public_key(self):
        """
        Get the public key from SoftHSM
        """

    def sign(self, message: bytes):
        """
        Sign a message with a key from SoftHSM
        """


class HsmFactory:
    """
    Create HSMs from HSMInfo configs
    """

    @staticmethod
    def from_hsm_info(hsm_info: HsmInfo, hash_type: HashType):
        """
        Create an HSM instance from hsm_info protobuf
        """

        if hsm_info.hsm_type == HsmType.SoftHSM:
            return SoftHsm(
                uri=hsm_info.pkcs11_uri,
                hash_type=hash_type,
            )
