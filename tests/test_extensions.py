"""
Unit tests for extensions
"""

from cryptography import x509

from autocsr.extensions import Extension
from autocsr.utils import load_csr

example_extension_config = {
    "subject": {"common_name": "test common name"},
    "key_path": "./fixtures/test.key",
    "output_path": "./fixtures/test.csr",
    "extensions": [
        {"extension_type": "OCSPNoCheck"},
        {"extension_type": "PrecertPoison"},
        {"subject_key_identifier": {"b64_digest": "dGVzdCBiNjQgZGlnZXN0"}},
        {"basic_constraints": {"ca": True, "path_length": 123}},
        {"policy_constraints": {"require_explicit_policy": 123}},
        {
            "certificate_policies": {
                "policies": [
                    {
                        "policy_identifier": "1.2.3.4",
                        "string_qualifiers": ["test qualifier 1", "test qualifier 2"],
                        "user_qualifiers": [
                            {
                                "notice_reference": {
                                    "organization": "test_org",
                                    "notice_numbers": [1, 2, 3],
                                },
                                "explicit_text": "test explicit text",
                            },
                        ],
                    }
                ]
            }
        },
        {"extended_key_usage": {"usages": ["1.2.3.4.5", "2.3.4.5.6", "serverAuth"]}},
        {"tls_feature": {"features": ["status_request", "status_request_v2"]}},
        {"inhibit_any_policy": {"skip_certs": 12345}},
        {
            "key_usage": {
                "digital_signature": True,
                "content_commitment": False,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": True,
                "key_cert_sign": False,
                "crl_sign": True,
                "encipher_only": False,
                "decipher_only": True,
            }
        },
        {
            "authority_key_identifier": {
                "authority_cert_issuer": [
                    {"rfc_822_name": {"value": "Test RFC Name"}},
                    {"dns_name": {"value": "Test DNS Name"}},
                    {"uniform_resource_identifier": {"value": "Test Resource Name"}},
                    {
                        "directory_name": {
                            "value": {
                                "attributes": [
                                    {"oid": "1.2.3.4", "value": "test_attribute"}
                                ]
                            }
                        }
                    },
                    {"registered_id": {"oid": "1.2.3.4.5"}},
                    {"ip_address": {"value": "123.12.123.55"}},
                ],
                "authority_cert_serial_number": 12345,
            }
        },
        {
            "authority_information_access": {
                "descriptions": [
                    {
                        "access_method": "1.2.3.4.5",
                        "access_location": {"dns_name": {"value": "Test DNS Access"}},
                    }
                ]
            }
        },
        {
            "subject_information_access": {
                "descriptions": [
                    {
                        "access_method": "1.2.3.4.5.6",
                        "access_location": {"ip_address": {"value": "11.22.33.44"}},
                    }
                ]
            }
        },
        {
            "crl_distribution_points": {
                "distribution_points": [
                    {
                        "relative_name": {
                            "attributes": [{"oid": "1.8.8.8", "value": "relative_name"}]
                        },
                        "reasons": ["superseded", "ca_compromise"],
                        "crl_issuer": [{"dns_name": {"value": "crl_issuer"}}],
                    }
                ]
            }
        },
        {
            "freshest_crl": {
                "distribution_points": [
                    {
                        "relative_name": {
                            "attributes": [
                                {"oid": "1.2.3.88", "value": "relative_name"}
                            ]
                        },
                        "reasons": ["superseded", "ca_compromise"],
                        "crl_issuer": [{"dns_name": {"value": "crl_issuer"}}],
                    }
                ]
            }
        },
        {
            "name_constraints": {
                "permitted_subtrees": [{"dns_name": {"value": "permitted_subtrees"}}],
                "excluded_subtrees": [
                    {"dns_name": {"value": "excluded_subtrees"}},
                    {"dns_name": {"value": "other excluded_subtrees"}},
                ],
            }
        },
        {
            "subject_alternative_name": {
                "general_names": [
                    {"dns_name": {"value": "first alternative name"}},
                    {"dns_name": {"value": "second alternative name"}},
                ]
            }
        },
        {
            "issuer_alternative_name": {
                "general_names": [
                    {"dns_name": {"value": "first issuer alternative name"}},
                    {"dns_name": {"value": "second issuer alternative name"}},
                ]
            }
        },
    ],
}


def test_extension():
    """
    Test all extensions in example config
    """

    proto = load_csr(example_extension_config)

    for extension in proto.extensions:
        extval = Extension.from_proto(extension)

        assert isinstance(
            extval, x509.extensions.ExtensionType
        ), f"Correct {extension} should inherit from x509 ExtensionType"
