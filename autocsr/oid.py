"""Create wrapped Object Identifiers."""

import re
import typing

from cryptography import x509
from cryptography.x509.oid import _OID_NAMES


class ObjectIdentifier(x509.ObjectIdentifier):
    """A wrapped Object Identifier with custom factory methods."""

    @staticmethod
    def is_dotted_string(oid: str) -> bool:
        """Evaluate if a string is a dotted string."""
        if isinstance(oid, str) and re.fullmatch("^([0-9]+[.])*[0-9]+$", oid):
            return True

        return False

    @staticmethod
    def reverse_lookup(known_name: str) -> typing.Optional[str]:
        """Lookup dotted string from a known ObjectIdentifier name."""
        for oid, name in _OID_NAMES.items():
            if known_name == name:
                return oid.dotted_string

        return None

    @classmethod
    def from_string(cls, oid: str):
        """
        Create an ObjectIdentifier.

        Create an ObjectIdentifier from a dotted string or associated name.
        """
        if cls.is_dotted_string(oid):
            return cls(oid)

        dotted_string = cls.reverse_lookup(oid)

        if dotted_string:
            return cls(dotted_string)

        raise TypeError(f"Unknown OID: {oid}")
