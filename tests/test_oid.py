"""
Unit tests for custom Object Identifier wrapper
"""

from unittest import TestCase

from autocsr.oid import ObjectIdentifier


class TestObjectIdentifier(TestCase):
    """
    Tests for custom Object Identifier wrapper
    """

    def test_dotted_string(self):
        """
        Validate that dotted strings are corectly identified
        """

        good_dotted_string = "1.2.3.4.5.66.7890"
        not_dotted_string = "Normal String"

        self.assertTrue(
            ObjectIdentifier.is_dotted_string(good_dotted_string),
            "Correct dotted string should pass",
        )
        self.assertFalse(
            ObjectIdentifier.is_dotted_string(not_dotted_string),
            "Incorrect dotted strings should fail",
        )

    def test_reverse_lookup(self):
        """
        Validate that oids can correctly been looked up from names
        """

        good_name = "issuerAltName"
        bad_name = "randomName"

        self.assertIsNotNone(
            ObjectIdentifier.reverse_lookup(good_name),
            "Correct name lookups should pass",
        )
        self.assertIsNone(
            ObjectIdentifier.reverse_lookup(bad_name), "Bad name lookups should fail"
        )

    def test_from_string(self):
        """
        Test creating an ObjectIdentifier from dotted strings and names
        """

        dotted_string = "1.2.3.4.5.67890"
        name = "issuerAltName"

        dotted_string_oid = ObjectIdentifier.from_string(dotted_string)
        name_oid = ObjectIdentifier.from_string(name)

        self.assertIsInstance(
            dotted_string_oid,
            ObjectIdentifier,
            "Should be able to create ObjectIdentifier from dotted string",
        )
        self.assertIsInstance(
            name_oid,
            ObjectIdentifier,
            "Should be able to create ObjectIdentifier from name",
        )
