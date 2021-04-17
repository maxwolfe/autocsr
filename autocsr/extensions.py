"""
Wrappers to turn configs into x509 Extensions
"""

from base64 import b64decode
from datetime import datetime
from ipaddress import ip_address
from typing import Iterable

from cryptography.x509 import extensions, general_name
from cryptography.x509 import name as x509_name

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


# Currently unsupported by autocsr
class PrecertificateSignedCertificateTimestamps(
    extensions.PrecertificateSignedCertificateTimestamps
):
    """
    Wrapper for PrecertificateSignedCertificateTimestamps Extension from config
    file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a PrecertificateSignedCertificateTimestamps from a protobuf
        """

        raise TypeError(
            "autocsr currently does not support signed certificate timestamps"
        )


# Currently unsupported by autocsr
class SignedCertificateTimestamps(extensions.SignedCertificateTimestamps):
    """
    Wrapper for SignedCertificateTimestamps Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a SignedCertificateTimestamps from a protobuf
        """

        raise TypeError(
            "autocsr currently does not support signed certificate timestamps"
        )


# Unsupported by cryptography
class OCSPNonce(extensions.OCSPNonce):
    """
    Wrapper for OCSPNonce Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a OCSPNonce from a protobuf
        """

        this_extension = extension.ocsp_nonce

        return cls(nonce=b64decode(this_extension.b64_nonce.encode()))


class RFC822Name(general_name.RFC822Name):
    """
    Wrapper for RFC822Name general name from config file
    """

    @classmethod
    def from_proto(cls, name: CSR_EXTENSION.GeneralName):
        """
        Create a RFC822Name from a protobuf
        """

        this_name = name.rfc_822_name

        return cls(value=this_name.value)


class DNSName(general_name.DNSName):
    """
    Wrapper for DNSName general name from config file
    """

    @classmethod
    def from_proto(cls, name: CSR_EXTENSION.GeneralName):
        """
        Create a DNSName from a protobuf
        """

        this_name = name.dns_name

        return cls(value=this_name.value)


class UniformResourceIdentifier(general_name.UniformResourceIdentifier):
    """
    Wrapper for UniformResourceIdentifier general name from config file
    """

    @classmethod
    def from_proto(cls, name: CSR_EXTENSION.GeneralName):
        """
        Create a UniformResourceIdentifier from a protobuf
        """

        this_name = name.uniform_resource_identifier

        return cls(value=this_name.value)


class NameAttribute(x509_name.NameAttribute):
    """
    Wrapper for NameAttribute from config file
    """

    @classmethod
    def from_proto(cls, attribute: CSR_EXTENSION.NameAttribute):
        """
        Create a NameAttribute from a config file
        """

        return cls(
            oid=ObjectIdentifier.from_string(attribute.oid),
            value=attribute.value,
        )


class Name(x509_name.Name):
    """
    Wrapper for Name from config file
    """

    @classmethod
    def from_proto(cls, name: CSR_EXTENSION.Name):
        """
        Create a Name from a config file
        """

        return cls(
            attributes=(
                NameAttribute.from_proto(attribute) for attribute in name.attributes
            ),
        )


class DirectoryName(general_name.DirectoryName):
    """
    Wrapper for DirectoryName general name from config file
    """

    @classmethod
    def from_proto(cls, name: CSR_EXTENSION.GeneralName):
        """
        Create a DirectoryName from a protobuf
        """

        this_name = name.directory_name

        return cls(value=Name.from_proto(this_name.value))


class RegisteredID(general_name.RegisteredID):
    """
    Wrapper for RegisteredID general name from config file
    """

    @classmethod
    def from_proto(cls, name: CSR_EXTENSION.GeneralName):
        """
        Create a RegisteredID from a protobuf
        """

        this_name = name.registered_id

        return cls(value=ObjectIdentifier.from_string(this_name.oid))


class IPAddress(general_name.IPAddress):
    """
    Wrapper for an IPAddress general name from config file
    """

    @classmethod
    def from_proto(cls, name: CSR_EXTENSION.GeneralName):
        """
        Create a IPAddress from a protobuf
        """

        this_name = name.ip_address

        return cls(value=ip_address(this_name.value))


# Untested
class OtherName(general_name.OtherName):
    """
    Wrapper for an OtherName general name from config file
    """

    @classmethod
    def from_proto(cls, name: CSR_EXTENSION.GeneralName):
        """
        Create a OtherName from a protobuf
        """

        this_name = name.other_name

        return cls(
            type_id=ObjectIdentifier.from_string(this_name.oid),
            value=b64decode(this_name.b64_value.encode()),
        )


class GeneralName:
    """
    Factory for creating General Names from a config
    """

    name_types = {
        "rfc_822_name": RFC822Name,
        "dns_name": DNSName,
        "uniform_resource_identifier": UniformResourceIdentifier,
        "directory_name": DirectoryName,
        "registered_id": RegisteredID,
        "ip_address": IPAddress,
        "other_name": OtherName,
    }

    @staticmethod
    def from_proto(name: CSR_EXTENSION.GeneralName) -> general_name.GeneralName:
        """
        Create a GeneralName instance from a protobuf
        """

        return GeneralName.name_types.get(name.WhichOneof("name")).from_proto(name)


class AuthorityKeyIdentifier(extensions.AuthorityKeyIdentifier):
    """
    Wrapper for AuthorityKeyIdentifier Extension from config file
    """

    @classmethod
    def from_proto(cls, extension: CSR_EXTENSION):
        """
        Create a AuthorityKeyIdentifier from a protobuf
        """

        this_extension = extension.authority_key_identifier

        key_identifier = this_extension.key_identifier
        authority_cert_serial_number = this_extension.authority_cert_serial_number

        if not key_identifier:
            key_identifier = None

        if not authority_cert_serial_number:
            authority_cert_serial_number = None

        return cls(
            key_identifier=key_identifier,
            authority_cert_issuer=(
                GeneralName.from_proto(name)
                for name in this_extension.authority_cert_issuer
            ),
            authority_cert_serial_number=authority_cert_serial_number,
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
        # "precertificate_signed_certificate_timestamps": PrecertificateSignedCertificateTimestamps,
        # 'signed_certificate_timestamps': SignedCertificateTimestamps,
        # "ocsp_nonce": OCSPNonce,
        "authority_key_identifier": AuthorityKeyIdentifier,
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
