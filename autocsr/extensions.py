"""
Wrappers to turn configs into x509 Extensions
"""

from base64 import b64decode
from datetime import datetime
from typing import Iterable

from cryptography.x509 import extensions

import autocsr.protos.csr_pb2 as proto
from autocsr.oid import ObjectIdentifier

DATE_FMT = "%d/%m/%Y %H:%M:%S"

CSR_EXTENSION = proto.CertificateSigningRequest.Extension


class ExtensionType:
    """
    Factory for returning a parameter-less extension from a protobuf
    """

    @staticmethod
    def from_proto(extension: CSR_EXTENSION) -> extensions.ExtensionType:
        """
        Return an extension instance based on enum extension type
        """

        this_extension = extension.extension_type

        if this_extension == extension.ExtensionType.OCSPNoCheck:
            return extensions.OCSPNoCheck()

        if this_extension == extension.ExtensionType.PrecertPoison:
            return extensions.PrecertPoison()

        raise TypeError(f"No known extension: {this_extension}")


# Unsupported by cryptography
class CRLNumber(extensions.CRLNumber):
    """
    Wrapper for CRLNumber Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a CRLNumber extension from a protobuf
        """

        this_extension = extension.crl_number

        return cls(
            crl_number=this_extension.crl_number,
        )


class SubjectKeyIdentifier(extensions.SubjectKeyIdentifier):
    """
    Wrapper for SubjectKeyIdentifier Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a SubjectKeyIdentifier extension from a protobuf
        """

        this_extension = extension.subject_key_identifier

        return cls(digest=b64decode(this_extension.b64_digest.encode()))


class BasicConstraints(extensions.BasicConstraints):
    """
    Wrapper for BasicConstraints Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a BasicConstraints extension from a protobuf
        """

        this_extension = extension.basic_constraints

        path_length = this_extension.path_length

        if not path_length:
            path_length = None

        return cls(
            ca=this_extension.ca,
            path_length=path_length,
        )


# Unsupported by cryptography
class DeltaCRLIndicator(extensions.DeltaCRLIndicator):
    """
    Wrapper for DeltaCRLIndicator Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a DeltaCRLIndicator extension from a protobuf
        """

        this_extension = extension.delta_crl_indicator

        return cls(crl_number=this_extension.crl_number)


class PolicyConstraints(extensions.PolicyConstraints):
    """
    Wrapper for PolicyConstraints Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a PolicyConstraints Extension from a protobuf
        """

        this_extension = extension.policy_constraints

        require_explicit_policy = this_extension.require_explicit_policy
        inhibit_policy_mapping = this_extension.inhibit_policy_mapping

        if not require_explicit_policy:
            require_explicit_policy = None

        if not inhibit_policy_mapping:
            inhibit_policy_mapping = None

        return cls(
            require_explicit_policy=require_explicit_policy,
            inhibit_policy_mapping=inhibit_policy_mapping,
        )


class NoticeReference(extensions.NoticeReference):
    """
    Wrapper for NoticeReference from config file
    """

    @classmethod
    def from_proto(cls, notice: CSR_EXTENSION.NoticeReference):
        """
        Create a Noticereference from a protobuf
        """

        organization = notice.organization

        if not organization:
            organization = None

        return cls(
            organization=organization,
            notice_numbers=notice.notice_numbers,
        )


class UserNotice(extensions.UserNotice):
    """
    Wrapper for UserNotice from config file
    """

    @classmethod
    def from_proto(cls, notices: Iterable[CSR_EXTENSION.UserNotice]):
        """
        Create a list of UserNotice form a protobuf
        """

        information_list = []

        for notice in notices:
            notice_reference = NoticeReference.from_proto(notice.notice_reference)
            explicit_text = notice.explicit_text

            if not notice_reference:
                notice_reference = None

            if not explicit_text:
                explicit_text = None

            information_list.append(
                cls(
                    notice_reference=notice_reference,
                    explicit_text=explicit_text,
                )
            )

        return information_list


class PolicyInformation(extensions.PolicyInformation):
    """
    Wrapper for PolicyInformation from config file
    """

    @classmethod
    def from_proto(cls, policies: Iterable[CSR_EXTENSION.PolicyInformation]):
        """
        Create a list of PolicyInformation from a protobuf
        """

        information_list = []

        for policy in policies:
            policy_qualifiers = []

            for string in policy.string_qualifiers:
                policy_qualifiers.append(string)

            for user_notice in UserNotice.from_proto(policy.user_qualifiers):
                policy_qualifiers.append(user_notice)

            information_list.append(
                cls(
                    policy_identifier=ObjectIdentifier.from_string(
                        policy.policy_identifier
                    ),
                    policy_qualifiers=policy_qualifiers,
                )
            )

        return information_list


class CertificatePolicies(extensions.CertificatePolicies):
    """
    Wrapper for CertificatePolicies Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a CertificatePolicies extension from a protobuf
        """

        this_extension = extension.certificate_policies

        return cls(policies=PolicyInformation.from_proto(this_extension.policies))


class ExtendedKeyUsage(extensions.ExtendedKeyUsage):
    """
    Wrapper for ExtendedKeyUsage extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a ExtendedKeyUsage extension from a protobuf
        """

        this_extension = extension.extended_key_usage

        return cls(
            usages=(ObjectIdentifier.from_string(oid) for oid in this_extension.usages),
        )


class TLSFeature(extensions.TLSFeature):
    """
    Wrapper for TLSFeature Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a TLSFeature extension from a protobuf
        """

        this_extension = extension.tls_feature

        return cls(
            features=(
                extensions.TLSFeatureType(feature)
                for feature in this_extension.features
            )
        )


class InhibitAnyPolicy(extensions.InhibitAnyPolicy):
    """
    Wrapper for InhibitAnyPolicy Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a InhibitAnyPolicy extension from a protobuf
        """

        this_extension = extension.inhibit_any_policy

        return cls(
            skip_certs=this_extension.skip_certs,
        )


class KeyUsage(extensions.KeyUsage):
    """
    Wrapper for KeyUsage Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a KeyUsage extension from a protobuf
        """

        this_extension = extension.key_usage

        return cls(
            digital_signature=this_extension.digital_signature,
            content_commitment=this_extension.content_commitment,
            key_encipherment=this_extension.key_encipherment,
            data_encipherment=this_extension.data_encipherment,
            key_agreement=this_extension.key_agreement,
            key_cert_sign=this_extension.key_cert_sign,
            crl_sign=this_extension.crl_sign,
            encipher_only=this_extension.encipher_only,
            decipher_only=this_extension.decipher_only,
        )


class ReasonFlags:
    """
    Map int enum ReasonFlags to exceptions.ReasonFlag enums
    """

    ProtoFlag = CSR_EXTENSION.ReasonFlags
    ExtFlag = extensions.ReasonFlags

    flags = {
        ProtoFlag.unspecified: ExtFlag.unspecified,
        ProtoFlag.key_compromise: ExtFlag.key_compromise,
        ProtoFlag.ca_compromise: ExtFlag.ca_compromise,
        ProtoFlag.affiliation_changed: ExtFlag.affiliation_changed,
        ProtoFlag.superseded: ExtFlag.superseded,
        ProtoFlag.cessation_of_operation: ExtFlag.cessation_of_operation,
        ProtoFlag.privilege_withdrawn: ExtFlag.privilege_withdrawn,
        ProtoFlag.aa_compromise: ExtFlag.aa_compromise,
        ProtoFlag.remove_from_crl: ExtFlag.remove_from_crl,
    }

    @staticmethod
    def from_proto(reason: ProtoFlag) -> ExtFlag:
        """
        Convert a protobuf version ReasonFlag into the extensions version
        """

        return ReasonFlags.flags[reason]


# Unsupported by cryptography
class CRLReason(extensions.CRLReason):
    """
    Wrapper for CRLReason Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a CRLReason extension from a protobuf
        """

        this_extension = extension.crl_reason

        return cls(
            reason=ReasonFlags.from_proto(this_extension.reason),
        )


# Unsupported by cryptography
class InvalidityDate(extensions.InvalidityDate):
    """
    Wrapper for InvalidityDate Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a InvalidityDate from a protobuf
        """

        this_extension = extension.invalidity_date
        return cls(
            invalidity_date=datetime.strptime(this_extension.invalidity_date, DATE_FMT),
        )


class Extension:
    """
    A factory for creating x509 Extensions from config
    """

    extension_list = {
        "extension_type": ExtensionType,
        #  "crl_number": CRLNumber,
        "key_usage": KeyUsage,
        "subject_key_identifier": SubjectKeyIdentifier,
        "basic_constraints": BasicConstraints,
        #  "delta_crl_indicator": DeltaCRLIndicator,
        "policy_constraints": PolicyConstraints,
        "certificate_policies": CertificatePolicies,
        "extended_key_usage": ExtendedKeyUsage,
        "tls_feature": TLSFeature,
        "inhibit_any_policy": InhibitAnyPolicy,
        #  "crl_reason": CRLReason,
        #  "invalidity_date": InvalidityDate,
    }

    @staticmethod
    def get_extension_type(extension: CSR_EXTENSION) -> extensions.ExtensionType:
        """
        Get the custom extension wrapper for an extension protobuf
        """

        return Extension.extension_list.get(extension.WhichOneof("extension"))

    @staticmethod
    def from_proto(extension: CSR_EXTENSION) -> extensions.ExtensionType:
        """
        Factory for creating extensions from an extension proto
        """

        extension_type = Extension.get_extension_type(extension)

        return extension_type.from_proto(extension)
