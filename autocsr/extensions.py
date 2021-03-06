"""Wrappers to turn configs into x509 Extensions."""

from base64 import b64decode
from ipaddress import ip_address
from typing import Iterable

from cryptography.x509 import extensions, general_name
from cryptography.x509 import name as x509_name

import autocsr.protos.csr_pb2 as proto
from autocsr.oid import ObjectIdentifier

CsrExtension = proto.CertificateSigningRequest.Extension


class ExtensionType:
    """Factory for returning a parameter-less extension from a protobuf."""

    @staticmethod
    def from_proto(extension: CsrExtension) -> extensions.ExtensionType:
        """
        Return an extension instance based on enum extension type.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a CSR Extension.
        :rtype: :class:`cryptography.x509.extensions.ExtensionType`
        """
        this_extension = extension.extension_type

        if this_extension == extension.ExtensionType.OCSPNoCheck:
            return extensions.OCSPNoCheck()

        if this_extension == extension.ExtensionType.PrecertPoison:
            return extensions.PrecertPoison()

        raise TypeError(f"No known extension: {this_extension}")


class SubjectKeyIdentifier(extensions.SubjectKeyIdentifier):
    """Wrapper for SubjectKeyIdentifier Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a SubjectKeyIdentifier extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a SubjectKeyIdentifier Extension.
        :rtype: :class:`cryptography.x509.extensions.SubjectKeyIdentifier`
        """
        this_extension = extension.subject_key_identifier

        return cls(digest=b64decode(this_extension.b64_digest.encode()))


class BasicConstraints(extensions.BasicConstraints):
    """Wrapper for BasicConstraints Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a BasicConstraints extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a BasicConstraints Extension.
        :rtype: :class:`cryptography.x509.extensions.BasicConstraints`
        """
        this_extension = extension.basic_constraints

        path_length = this_extension.path_length

        if not path_length:
            path_length = None

        return cls(
            ca=this_extension.ca,
            path_length=path_length,
        )


class PolicyConstraints(extensions.PolicyConstraints):
    """Wrapper for PolicyConstraints Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a PolicyConstraints Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a PolicyConstraints Extension.
        :rtype: :class:`cryptography.x509.extensions.PolicyConstraints`
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
    """Wrapper for NoticeReference from config file."""

    @classmethod
    def from_proto(cls, notice: CsrExtension.NoticeReference):
        """
        Create a NoticeReference from a protobuf.

        :param CsrExtension.NoticeReference notice: A protobuf representation of a NoticeReference.
        :return: A `cryptography` representation of a NoticeReference.
        :rtype: :class:`cryptography.x509.extensions.NoticeReference`
        """
        organization = notice.organization

        if not organization:
            organization = None

        return cls(
            organization=organization,
            notice_numbers=notice.notice_numbers,
        )


class UserNotice(extensions.UserNotice):
    """Wrapper for UserNotice from config file."""

    @classmethod
    def from_proto(
        cls, notices: Iterable[CsrExtension.UserNotice]
    ) -> Iterable[extensions.UserNotice]:
        """
        Create a list of UserNotice form a protobuf.

        :param Iterable[CsrExtension.UserNotice] notices: A protobuf representation of UserNotices.
        :return: A `cryptography` representation of UserNotices.
        :rtype: Iterable[:class:`cryptography.x509.extensions.UserNotice`]
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
    """Wrapper for PolicyInformation from config file."""

    @classmethod
    def from_proto(cls, policies: Iterable[CsrExtension.PolicyInformation]):
        """
        Create a list of PolicyInformation from a protobuf.

        :param Iterable[CsrExtension.PolicyInformation] policies: A protobuf of PolicyInformations
        :return: A `cryptography` representation of PolicyInformations.
        :rtype: Iterable[:class:`cryptography.x509.extensions.PolicyInformation`]
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
    """Wrapper for CertificatePolicies Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a CertificatePolicies Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a CertificatePolicies Extension.
        :rtype: :class:`cryptography.x509.extensions.CertificatePolicies`
        """
        this_extension = extension.certificate_policies

        return cls(policies=PolicyInformation.from_proto(this_extension.policies))


class ExtendedKeyUsage(extensions.ExtendedKeyUsage):
    """Wrapper for ExtendedKeyUsage extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a ExtendedKeyUsage Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a ExtendedKeyUsage Extension.
        :rtype: :class:`cryptography.x509.extensions.ExtendedKeyUsage`
        """
        this_extension = extension.extended_key_usage

        return cls(
            usages=(ObjectIdentifier.from_string(oid) for oid in this_extension.usages),
        )


class TLSFeature(extensions.TLSFeature):
    """Wrapper for TLSFeature Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a TLSFeature Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a TLSFeature Extension.
        :rtype: :class:`cryptography.x509.extensions.TLSFeature`
        """
        this_extension = extension.tls_feature

        return cls(
            features=(
                extensions.TLSFeatureType(feature)
                for feature in this_extension.features
            )
        )


class InhibitAnyPolicy(extensions.InhibitAnyPolicy):
    """Wrapper for InhibitAnyPolicy Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a InhibitAnyPolicy Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a InhibitAnyPolicy Extension.
        :rtype: :class:`cryptography.x509.extensions.InhibitAnyPolicy`
        """
        this_extension = extension.inhibit_any_policy

        return cls(
            skip_certs=this_extension.skip_certs,
        )


class KeyUsage(extensions.KeyUsage):
    """Wrapper for KeyUsage Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a KeyUsage Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a KeyUsage Extension.
        :rtype: :class:`cryptography.x509.extensions.KeyUsage`
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
    """Map int enum ReasonFlags to exceptions.ReasonFlag enums."""

    ProtoFlag = CsrExtension.ReasonFlags
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
        Convert a protobuf version ReasonFlag into the `cryptography` version.

        :param ProtoFlag reason: A protobuf representation of a ReasonFlag.
        :return: A `cryptography` representation of a ReasonFlag.
        :rtype: :class:`cryptography.x509.extensions.ReasonFlags`
        """
        return ReasonFlags.flags[reason]


class RFC822Name(general_name.RFC822Name):
    """Wrapper for RFC822Name general name from config file."""

    @classmethod
    def from_proto(cls, name: CsrExtension.GeneralName):
        """
        Create a RFC822Name from a protobuf.

        :param CsrExtension.GeneralName name: A protobuf representation of a RFC822Name.
        :return: A `cryptography` representation of a RFC822Name.
        :rtype: :class:`cryptography.x509.general_name.RFC822Name`
        """
        this_name = name.rfc_822_name

        return cls(value=this_name.value)


class DNSName(general_name.DNSName):
    """Wrapper for DNSName general name from config file."""

    @classmethod
    def from_proto(cls, name: CsrExtension.GeneralName):
        """
        Create a DNSName from a protobuf.

        :param CsrExtension.GeneralName name: A protobuf representation of a DNSName.
        :return: A `cryptography` representation of a DNSName.
        :rtype: :class:`cryptography.x509.general_name.DNSName`
        """
        this_name = name.dns_name

        return cls(value=this_name.value)


class UniformResourceIdentifier(general_name.UniformResourceIdentifier):
    """Wrapper for UniformResourceIdentifier general name from config file."""

    @classmethod
    def from_proto(cls, name: CsrExtension.GeneralName):
        """
        Create a UniformResourceIdentifier from a protobuf.

        :param CsrExtension.GeneralName name: A protobuf of a UniformResourceIdentifier.
        :return: A `cryptography` representation of a UniformResourceIdentifier.
        :rtype: :class:`cryptography.x509.general_name.UniformResourceIdentifier`
        """
        this_name = name.uniform_resource_identifier

        return cls(value=this_name.value)


class NameAttribute(x509_name.NameAttribute):
    """Wrapper for NameAttribute from config file."""

    @classmethod
    def from_proto(cls, attribute: CsrExtension.NameAttribute):
        """
        Create a NameAttribute from a config file.

        :param CsrExtension.NameAttribute attribute: A protobuf representation of a NameAttribute.
        :return: A `cryptography` representation of a NameAttribute.
        :rtype: :class:`cryptography.x509.name.NameAttribute`
        """
        return cls(
            oid=ObjectIdentifier.from_string(attribute.oid),
            value=attribute.value,
        )


class Name(x509_name.Name):
    """Wrapper for Name from config file."""

    @classmethod
    def from_proto(cls, name: CsrExtension.Name):
        """
        Create a Name from a config file.

        :param CsrExtension.Name name: A protobuf representation of a Name.
        :return: A `cryptography` representation of a Name.
        :rtype: :class:`cryptography.x509.name.Name`
        """
        return cls(
            attributes=(
                NameAttribute.from_proto(attribute) for attribute in name.attributes
            ),
        )


class RelativeDistinguishedName(x509_name.RelativeDistinguishedName):
    """Wrapper for RelativeDistinguishedName from config file."""

    @classmethod
    def from_proto(cls, name: CsrExtension.Name):
        """
        Create a RelativeDistinguishedName from a config file.

        :param CsrExtension.Name name: A protobuf representation of a RelativeDistinguishedName.
        :return: A `cryptography` representation of a RelativeDistinguishedName.
        :rtype: :class:`cryptography.x509.name.RelativeDistinguishedName`
        """
        return cls(
            attributes=(
                NameAttribute.from_proto(attribute) for attribute in name.attributes
            ),
        )


class DirectoryName(general_name.DirectoryName):
    """Wrapper for DirectoryName general name from config file."""

    @classmethod
    def from_proto(cls, name: CsrExtension.GeneralName):
        """
        Create a DirectoryName from a protobuf.

        :param CsrExtension.GeneralName name: A protobuf representation of a DirectoryName.
        :return: A `cryptography` representation of a DirectoryName.
        :rtype: :class:`cryptography.x509.general_name.DirectoryName`
        """
        this_name = name.directory_name

        return cls(value=Name.from_proto(this_name.value))


class RegisteredID(general_name.RegisteredID):
    """Wrapper for RegisteredID general name from config file."""

    @classmethod
    def from_proto(cls, name: CsrExtension.GeneralName):
        """
        Create a RegisteredID from a protobuf.

        :param CsrExtension.GeneralName name: A protobuf representation of a RegisteredID.
        :return: A `cryptography` representation of a RegisteredID.
        :rtype: :class:`cryptography.x509.general_name.RegisteredID`
        """
        this_name = name.registered_id

        return cls(value=ObjectIdentifier.from_string(this_name.oid))


class IPAddress(general_name.IPAddress):
    """Wrapper for an IPAddress general name from config file."""

    @classmethod
    def from_proto(cls, name: CsrExtension.GeneralName):
        """
        Create a IPAddress from a protobuf.

        :param CsrExtension.GeneralName name: A protobuf representation of a IPAddress.
        :return: A `cryptography` representation of a IPAddress.
        :rtype: :class:`cryptography.x509.general_name.IPAddress`
        """
        this_name = name.ip_address

        return cls(value=ip_address(this_name.value))


# Untested
class OtherName(general_name.OtherName):
    """Wrapper for an OtherName general name from config file."""

    @classmethod
    def from_proto(cls, name: CsrExtension.GeneralName):
        """
        Create a OtherName from a protobuf.

        :param CsrExtension.GeneralName name: A protobuf representation of a OtherName.
        :return: A `cryptography` representation of a OtherName.
        :rtype: :class:`cryptography.x509.general_name.OtherName`
        """
        this_name = name.other_name

        return cls(
            type_id=ObjectIdentifier.from_string(this_name.oid),
            value=b64decode(this_name.b64_value.encode()),
        )


class GeneralName:
    """Factory for creating General Names from a config."""

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
    def from_proto(name: CsrExtension.GeneralName) -> general_name.GeneralName:
        """
        Create a GeneralName instance from a protobuf.

        :param CsrExtension.GeneralName name: A protobuf representation of a GeneralName.
        :return: A `cryptography` representation of a GeneralName.
        :rtype: :class:`cryptography.x509.general_name.GeneralName`
        """
        return GeneralName.name_types.get(name.WhichOneof("name")).from_proto(name)


class AuthorityKeyIdentifier(extensions.AuthorityKeyIdentifier):
    """Wrapper for AuthorityKeyIdentifier Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a AuthorityKeyIdentifier Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a AuthorityKeyIdentifier Extension.
        :rtype: :class:`cryptography.x509.extensions.AuthorityKeyIdentifier`
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


class AccessDescription(extensions.AccessDescription):
    """Wrapper for AccessDescription from a config file."""

    @classmethod
    def from_proto(cls, description: CsrExtension.AccessDescription):
        """
        Create a AccessDescription from a protobuf.

        :param CsrExtension.AccessDescription description: A protobuf of a AccessDescription.
        :return: A `cryptography` representation of a AccessDescription.
        :rtype: :class:`cryptography.x509.extensions.AccessDescription`
        """
        return cls(
            access_method=ObjectIdentifier.from_string(description.access_method),
            access_location=GeneralName.from_proto(description.access_location),
        )


class AuthorityInformationAccess(extensions.AuthorityInformationAccess):
    """Wrapper for AuthorityInformationAccess Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a AuthorityInformationAccess Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a AuthorityInformationAccess Extension.
        :rtype: :class:`cryptography.x509.extensions.AuthorityInformationAccess`
        """
        this_extension = extension.authority_information_access

        return cls(
            descriptions=(
                AccessDescription.from_proto(description)
                for description in this_extension.descriptions
            )
        )


class SubjectInformationAccess(extensions.SubjectInformationAccess):
    """Wrapper for SubjectInformationAccess Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a SubjectInformationAccess Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a SubjectInformationAccess Extension.
        :rtype: :class:`cryptography.x509.extensions.SubjectInformationAccess`
        """
        this_extension = extension.subject_information_access

        return cls(
            descriptions=(
                AccessDescription.from_proto(description)
                for description in this_extension.descriptions
            )
        )


class DistributionPoint(extensions.DistributionPoint):
    """Wrapper for DistributionPoint from config file."""

    @classmethod
    def from_proto(cls, dist: CsrExtension.DistributionPoint):
        """
        Create a DistributionPoint from a protobuf.

        :param CsrExtension.DistributionPoint dist: A protobuf of a DistributionPoint.
        :return: A `cryptography` representation of a DistributionPoint.
        :rtype: :class:`cryptography.x509.extensions.DistributionPoint`
        """
        full_name = [GeneralName.from_proto(name) for name in dist.full_name]
        relative_name = RelativeDistinguishedName.from_proto(dist.relative_name)
        reasons = frozenset((ReasonFlags.from_proto(reason) for reason in dist.reasons))
        crl_issuer = [GeneralName.from_proto(name) for name in dist.crl_issuer]

        if not full_name:
            full_name = None

        if not relative_name:
            relative_name = None

        if not reasons:
            reasons = None

        if not crl_issuer:
            crl_issuer = None

        return cls(
            full_name=full_name,
            relative_name=relative_name,
            reasons=reasons,
            crl_issuer=crl_issuer,
        )


class CRLDistributionPoints(extensions.CRLDistributionPoints):
    """Wrapper for CRLDistributionPoints Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a CRLDistributionPoints Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a CRLDistributionPoints Extension.
        :rtype: :class:`cryptography.x509.extensions.CRLDistributionPoints`
        """
        this_extension = extension.crl_distribution_points

        return cls(
            distribution_points=(
                DistributionPoint.from_proto(dist)
                for dist in this_extension.distribution_points
            )
        )


class FreshestCRL(extensions.FreshestCRL):
    """Wrapper for FreshestCRL Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a FreshestCRL Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a FreshestCRL Extension.
        :rtype: :class:`cryptography.x509.extensions.FreshestCRL`
        """
        this_extension = extension.freshest_crl

        return cls(
            distribution_points=(
                DistributionPoint.from_proto(dist)
                for dist in this_extension.distribution_points
            )
        )


class NameConstraints(extensions.NameConstraints):
    """Wrapper for a NameConstraints extension from a config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a NameConstraints Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a NameConstraints Extension.
        :rtype: :class:`cryptography.x509.extensions.NameConstraints`
        """
        this_extension = extension.name_constraints

        return cls(
            permitted_subtrees=(
                GeneralName.from_proto(name)
                for name in this_extension.permitted_subtrees
            ),
            excluded_subtrees=(
                GeneralName.from_proto(name)
                for name in this_extension.excluded_subtrees
            ),
        )


class SubjectAlternativeName(extensions.SubjectAlternativeName):
    """Wrapper for SubjectAlternativeName Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a SubjectAlternativeName Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a SubjectAlternativeName Extension.
        :rtype: :class:`cryptography.x509.extensions.SubjectAlternativeName`
        """
        this_extension = extension.subject_alternative_name

        return cls(
            general_names=(
                GeneralName.from_proto(name) for name in this_extension.general_names
            ),
        )


class IssuerAlternativeName(extensions.IssuerAlternativeName):
    """Wrapper for IssuerAlternativeName Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a IssuerAlternativeName Extension from a protobuf.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a IssuerAlternativeName Extension.
        :rtype: :class:`cryptography.x509.extensions.IssuerAlternativeName`
        """
        this_extension = extension.issuer_alternative_name

        return cls(
            general_names=(
                GeneralName.from_proto(name) for name in this_extension.general_names
            ),
        )


class Extension:
    """A factory for creating x509 Extensions from config."""

    extension_list = {
        "extension_type": ExtensionType,
        # "crl_number": CRLNumber,
        "subject_key_identifier": SubjectKeyIdentifier,
        "basic_constraints": BasicConstraints,
        # "delta_crl_indicator": DeltaCRLIndicator,
        "policy_constraints": PolicyConstraints,
        "certificate_policies": CertificatePolicies,
        "extended_key_usage": ExtendedKeyUsage,
        "tls_feature": TLSFeature,
        "inhibit_any_policy": InhibitAnyPolicy,
        "key_usage": KeyUsage,
        # "crl_reason": CRLReason,
        # "invalidity_date": InvalidityDate,
        # "precertificate_signed_certificate_timestamps": PrecertificateSignedCertificateTimestamps,
        # 'signed_certificate_timestamps': SignedCertificateTimestamps,
        # "ocsp_nonce": OCSPNonce,
        "authority_key_identifier": AuthorityKeyIdentifier,
        "authority_information_access": AuthorityInformationAccess,
        "subject_information_access": SubjectInformationAccess,
        "crl_distribution_points": CRLDistributionPoints,
        "freshest_crl": FreshestCRL,
        "name_constraints": NameConstraints,
        "subject_alternative_name": SubjectAlternativeName,
        "issuer_alternative_name": IssuerAlternativeName,
        # "certificate_issuer": CertificateIssuer,
        # "issuing_distribution_point": IssuingDistributionPoint,
    }

    @staticmethod
    def _get_extension_type(extension: CsrExtension) -> extensions.ExtensionType:
        """Get the custom extension wrapper for an extension protobuf."""
        return Extension.extension_list.get(extension.WhichOneof("extension"))

    @staticmethod
    def from_proto(extension: CsrExtension) -> extensions.ExtensionType:
        """
        Create a `cryptography` Extension from a protobuf representation.

        :param CsrExtension extension: A protobuf representation of a CSR Extension.
        :return: A `cryptography` representation of a CSR Extension.
        :rtype: :class:`cryptography.x509.extensions.ExtensionType`
        """
        extension_type = Extension._get_extension_type(extension)

        return extension_type.from_proto(extension)
