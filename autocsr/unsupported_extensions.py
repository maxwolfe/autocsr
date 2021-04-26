"""Wrappers for x509 Extensions currently not supported."""

from base64 import b64decode
from datetime import datetime

from cryptography.x509 import extensions

import autocsr.protos.csr_pb2 as proto
from autocsr.extensions import GeneralName, ReasonFlags, RelativeDistinguishedName

CsrExtension = proto.CertificateSigningRequest.Extension

DATE_FMT = "%d/%m/%Y %H:%M:%S"


# Unsupported by cryptography
class CRLNumber(extensions.CRLNumber):
    """
    Wrapper for CRLNumber Extension from config file.

    :meta private:
    """

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """Create a CRLNumber extension from a protobuf."""
        this_extension = extension.crl_number

        return cls(
            crl_number=this_extension.crl_number,
        )


# Unsupported by cryptography
class DeltaCRLIndicator(extensions.DeltaCRLIndicator):
    """
    Wrapper for DeltaCRLIndicator Extension from config file.

    :meta private:
    """

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """Create a DeltaCRLIndicator extension from a protobuf."""
        this_extension = extension.delta_crl_indicator

        return cls(crl_number=this_extension.crl_number)


# Unsupported by cryptography
class CRLReason(extensions.CRLReason):
    """Wrapper for CRLReason Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """Create a CRLReason extension from a protobuf."""
        this_extension = extension.crl_reason

        return cls(
            reason=ReasonFlags.from_proto(this_extension.reason),
        )


# Unsupported by cryptography
class InvalidityDate(extensions.InvalidityDate):
    """Wrapper for InvalidityDate Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """Create a InvalidityDate from a protobuf."""
        this_extension = extension.invalidity_date

        return cls(
            invalidity_date=datetime.strptime(this_extension.invalidity_date, DATE_FMT),
        )


# Currently unsupported by autocsr
class PrecertificateSignedCertificateTimestamps(
    extensions.PrecertificateSignedCertificateTimestamps
):
    """
    Wrapper for PrecertificateSignedCertificateTimestamps.

    Wrapper for PrecertificateSignedCertificateTimestamps Extension from config
    file.
    """

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """
        Create a PrecertificateSignedCertificateTimestamps.

        Create a PrecertificateSignedCertificateTimestamps from a protobuf.
        """
        raise TypeError(
            "autocsr currently does not support signed certificate timestamps"
        )


# Currently unsupported by autocsr
class SignedCertificateTimestamps(extensions.SignedCertificateTimestamps):
    """Wrapper for SignedCertificateTimestamps Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """Create a SignedCertificateTimestamps from a protobuf."""
        raise TypeError(
            "autocsr currently does not support signed certificate timestamps"
        )


# Unsupported by cryptography
class OCSPNonce(extensions.OCSPNonce):
    """Wrapper for OCSPNonce Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """Create a OCSPNonce from a protobuf."""
        this_extension = extension.ocsp_nonce

        return cls(nonce=b64decode(this_extension.b64_nonce.encode()))


# Unsupported by cryptography
class CertificateIssuer(extensions.CertificateIssuer):
    """Wrapper for CertificateIssuer Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """Create a CertificateIssuer from a protobuf."""
        this_extension = extension.certificate_issuer

        return cls(
            general_names=(
                GeneralName.from_proto(name) for name in this_extension.general_names
            ),
        )


# Unsupported by cryptography
class IssuingDistributionPoint(extensions.IssuingDistributionPoint):
    """Wrapper for IssuingDistributionPoint Extension from config file."""

    @classmethod
    def from_proto(cls, extension: CsrExtension):
        """Create a IssuingDistributionPoint from a protobuf."""
        this_extension = extension.issuing_distribution_point

        full_name = [GeneralName.from_proto(name) for name in this_extension.full_name]
        relative_name = RelativeDistinguishedName.from_proto(
            this_extension.relative_name
        )
        reasons = frozenset(
            (
                ReasonFlags.from_proto(reason)
                for reason in this_extension.only_some_reasons
            )
        )

        if not full_name:
            full_name = None

        if not relative_name:
            relative_name = None

        if not reasons:
            reasons = None

        return cls(
            full_name=full_name,
            relative_name=relative_name,
            only_contains_user_certs=this_extension.only_contains_user_certs,
            only_contains_ca_certs=this_extension.only_contains_ca_certs,
            only_some_reasons=reasons,
            indirect_crl=this_extension.indirect_crl,
            only_contains_attribute_certs=this_extension.only_contains_attribute_certs,
        )
