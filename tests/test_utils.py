"""
Unit tests for autocsr utilities
"""

from tempfile import NamedTemporaryFile
from unittest import TestCase

import yaml

from autocsr.protos.csr_pb2 import CertificateSigningRequest
from autocsr.utils import load_csr, load_csrs_from_file


class TestUtils(TestCase):
    """
    Test utility functions for autocsr
    """

    config = {
        "subject": {
            "common_name": "Test CSR",
        },
        "key_info": {
            "key_path": "./fixtures/test.key",
        },
        "output_path": "./fixtures/test.csr",
        "hash_type": "SHA512",
    }
    config_list = {0: config}

    def validate_csr(self, csr: CertificateSigningRequest, config: dict):
        """
        Helper function for validating a generated CSR
        """

        self.assertIsInstance(
            csr,
            CertificateSigningRequest,
            "Loaded configuration must be instance of CSR Proto",
        )
        self.assertEqual(
            csr.subject.common_name,
            config["subject"]["common_name"],
            "Common name should match config file",
        )
        self.assertEqual(
            csr.key_info.key_path,
            config["key_info"]["key_path"],
            "Key path should match config file",
        )
        self.assertEqual(
            csr.output_path,
            config["output_path"],
            "Output path should match config file",
        )

    def test_load_csr(self):
        """
        Test load_csr utility on real data
        """

        csr_proto = load_csr(self.config)
        self.validate_csr(csr_proto, self.config)

    def test_load_csrs_from_file(self):
        """
        Test load_csrs_from_file utility on real data
        """

        fake_file = NamedTemporaryFile().name

        with open(fake_file, "w") as fake_config:
            fake_config.write(yaml.dump(self.config_list))

        for idx, csr in enumerate(load_csrs_from_file(fake_file)):
            self.validate_csr(csr, self.config_list[idx])
