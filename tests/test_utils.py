"""Unit tests for autocsr utilities."""

import os
from tempfile import NamedTemporaryFile
from unittest import TestCase
from unittest.mock import patch

import yaml

from autocsr.protos.csr_pb2 import CertificateSigningRequest
from autocsr.utils import (
    _load_csr,
    _load_csrs_from_jinja,
    _load_csrs_from_yaml,
    load_csrs_from_file,
)


class TestUtils(TestCase):
    """Test utility functions for autocsr."""

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
        """Validate a generated CSR."""
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
        """Test load_csr utility on real data."""
        csr_proto = _load_csr(self.config)
        self.validate_csr(csr_proto, self.config)

    def test_load_csrs_from_yaml(self):
        """Test load_csrs_from_yaml on real data."""
        fake_file = NamedTemporaryFile().name

        with open(fake_file, "w") as fake_config:
            fake_config.write(yaml.dump(self.config_list))

        for idx, csr in enumerate(_load_csrs_from_yaml(fake_file)):
            self.validate_csr(csr, self.config_list[idx])

    def test_load_csrs_from_jinja(self):
        """Test load_csrs_from_jinja on real data."""
        fake_file = NamedTemporaryFile().name
        yaml_config = yaml.dump(self.config_list)
        jinja_config = yaml_config.replace("Test", "{{ TEST }}")
        os.environ["TEST"] = "Test"

        self.assertIn(
            "{{ TEST }}",
            jinja_config,
            "Environment variable notation should be found in jinja config",
        )
        self.assertNotIn(
            "Test",
            jinja_config,
            "Environment variable data contents should not be found in jinja config",
        )

        with open(fake_file, "w") as fake_config:
            fake_config.write(jinja_config)

        for idx, csr in enumerate(_load_csrs_from_jinja(fake_file)):
            self.validate_csr(csr, self.config_list[idx])

    @patch("autocsr.utils._load_csrs_from_jinja")
    @patch("autocsr.utils._load_csrs_from_yaml")
    def test_load_csrs_from_file(self, mock_load_yaml, mock_load_jinja):
        """Test load_csrs_from_file utility on real data."""
        fake_yaml = NamedTemporaryFile(suffix=".yaml").name
        fake_jinja = NamedTemporaryFile(suffix=".jinja2").name

        load_csrs_from_file(fake_yaml)
        mock_load_yaml.assert_called_once_with(fake_yaml)
        mock_load_jinja.assert_not_called()

        load_csrs_from_file(fake_jinja)
        mock_load_yaml.assert_called_once_with(fake_yaml)
        mock_load_jinja.assert_called_once_with(fake_jinja)
