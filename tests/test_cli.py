"""Tests for the autocsr command line interface."""

import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest import TestCase

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from typer.testing import CliRunner

from autocsr.cli import app


class TestCli(TestCase):
    """Test command line interfaces."""

    config = {
        0: {
            "subject": {
                "common_name": "Test CSR",
            },
            "key_info": {
                "key_path": str(Path("tests/fixtures/test.key").absolute()),
            },
            "output_path": NamedTemporaryFile().name,
        },
    }

    def setUp(self):
        """Set up CLI Test."""
        self.cli = CliRunner()
        self.config_file = NamedTemporaryFile(suffix=".yaml").name

        with open(self.config_file, "w") as config:
            config.write(yaml.dump(self.config))

    def test_build(self):
        """Test creating CSRs from config files."""
        result = self.cli.invoke(
            app,
            ["build", self.config_file],
        )
        output_path = self.config[0]["output_path"]

        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            f"Created new CSR at {output_path}\n",
            "Should print success to user",
        )

    def test_create(self):
        """Test creating CSRs from a common name."""
        test_common_name = self.config[0]["subject"]["common_name"]
        test_key_path = NamedTemporaryFile().name
        test_output_path = self.config[0]["output_path"]

        result = self.cli.invoke(
            app,
            [
                "create",
                test_common_name,
            ],
            input=f"{test_key_path}\n{test_output_path}",
        )

        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            f"Where to store the new key? [./{test_common_name}.pem]: {test_key_path}\n"
            f"Where to store the new csr? [./{test_common_name}.csr]: {test_output_path}\n"
            f"Created new CSR at {test_output_path}\n",
            "Should print success to user",
        )

    def test_prompt(self):
        """Test creating CSRs from a user prompt."""
        test_common_name = self.config[0]["subject"]["common_name"]
        test_key_path = NamedTemporaryFile().name
        test_output_path = self.config[0]["output_path"]

        result = self.cli.invoke(
            app,
            [
                "prompt",
                test_common_name,
            ],
            input=f"{test_key_path}\n{test_output_path}",
        )

        self.maxDiff = None  # Helps with debugging long asserts
        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            f"Where to store the new key? [./{test_common_name}.pem]: {test_key_path}\n"
            f"Where to store the new csr? [./{test_common_name}.csr]: {test_output_path}\n"
            "What is your country identifier? (2 characters) []: \n"
            "What is your state or province name? []: \n"
            "What is your locality name? []: \n"
            "What is your organization name? []: \n"
            "What is your organizational unit name? []: \n"
            "What is your email address? []: \n"
            "What is the desired hash algorithm to use? (SHA256, SHA224, SHA384,"
            " SHA512, SHA512_224, SHA512_256, BLAKE2b, BLAKE2s, SHA3_224, SHA3_256,"
            " SHA3_384, SHA3_512, SHAKE128, SHAKE256) [SHA256]: \n"
            "What is the desired type of key? (RSA, DSA, EC) [RSA]: \n"
            "What is the desired key size? (1024, 2048, 4096) [2048]: \n"
            f"Created new CSR at {test_output_path}\n",
            "Should print success to user",
        )


class TestExamples(TestCase):
    """Tests for README examples."""

    def setUp(self):
        """Set up CLI Test."""
        self.cli = CliRunner()

    def test_create_basic(self):
        """Test create with no extra parameters example."""
        test_common_name = "My Common Name"

        result = self.cli.invoke(
            app,
            ["create", test_common_name],
        )

        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            f"Where to store the new key? [./{test_common_name}.pem]: \n"
            f"Where to store the new csr? [./{test_common_name}.csr]: \n"
            f"Created new CSR at ./{test_common_name}.csr\n",
            "Should print success to user",
        )

    def test_create_explicit(self):
        """Test create with explicit parameters example."""
        test_common_name = "My Common Name"
        test_key_path = NamedTemporaryFile().name
        test_output_path = NamedTemporaryFile().name

        result = self.cli.invoke(
            app,
            [
                "create",
                test_common_name,
                "--key-path",
                test_key_path,
                "--output-path",
                test_output_path,
            ],
        )

        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            f"Created new CSR at {test_output_path}\n",
            "Should print success to user",
        )

    def test_prompt(self):
        """Test prompting a user example."""
        test_common_name = "My Prompted CSR"
        result = self.cli.invoke(
            app,
            [
                "prompt",
                test_common_name,
            ],
        )

        self.maxDiff = None  # Helps with debugging long asserts
        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            f"Where to store the new key? [./{test_common_name}.pem]: \n"
            f"Where to store the new csr? [./{test_common_name}.csr]: \n"
            "What is your country identifier? (2 characters) []: \n"
            "What is your state or province name? []: \n"
            "What is your locality name? []: \n"
            "What is your organization name? []: \n"
            "What is your organizational unit name? []: \n"
            "What is your email address? []: \n"
            "What is the desired hash algorithm to use? (SHA256, SHA224, SHA384, "
            "SHA512, SHA512_224, SHA512_256, BLAKE2b, BLAKE2s, SHA3_224, "
            "SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256) [SHA256]: \n"
            "What is the desired type of key? (RSA, DSA, EC) [RSA]: \n"
            "What is the desired key size? (1024, 2048, 4096) [2048]: \n"
            f"Created new CSR at ./{test_common_name}.csr\n",
            "Should print success to user",
        )

    @pytest.mark.skipif(not Path("/tmp").exists(), reason="/tmp must be available")
    def test_build_simple(self):
        """Test building from the simple config file example."""
        test_config_file = str(Path("examples/quick_csr.yaml").absolute())
        result = self.cli.invoke(
            app,
            [
                "build",
                test_config_file,
            ],
        )
        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            "Created new CSR at /tmp/my_first_autocsr.csr\n",
            "Should print success to user",
        )

    @pytest.mark.skipif(not Path("/tmp").exists(), reason="/tmp must be available")
    def test_build_subject(self):
        """Test building from the subject config file example."""
        test_config_file = str(Path("examples/subject_example.yaml").absolute())
        result = self.cli.invoke(
            app,
            [
                "build",
                test_config_file,
            ],
        )
        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            "Created new CSR at /tmp/subject_example.csr\n",
            "Should print success to user",
        )

    @pytest.mark.skipif(not Path("/tmp").exists(), reason="/tmp must be available")
    def test_build_keys(self):
        """Test building from the key info config file example."""
        test_config_file = str(Path("examples/key_example.yaml").absolute())
        dsa_key = dsa.generate_private_key(
            key_size=2048,
        )
        with open("/tmp/my_dsa.key", "wb") as f:
            f.write(
                dsa_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption=serialization.NoEncryption,
                )
            )

        result = self.cli.invoke(
            app,
            [
                "build",
                test_config_file,
            ],
        )
        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            "Created new CSR at /tmp/my_rsa_autocsr.csr\n"
            "Created new CSR at /tmp/my_dsa_autocsr.csr\n"
            "Created new CSR at /tmp/my_ec_autocsr.csr\n",
            "Should print success to user",
        )

    @pytest.mark.skipif(not Path("/tmp").exists(), reason="/tmp must be available")
    def test_build_attributes(self):
        """Test building from the custom attributes config file example."""
        test_config_file = str(Path("examples/attribute_example.yaml").absolute())

        result = self.cli.invoke(
            app,
            [
                "build",
                test_config_file,
            ],
        )
        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            "Created new CSR at /tmp/my_attributes_autocsr.csr\n",
            "Should print success to user",
        )

    @pytest.mark.skipif(not Path("/tmp").exists(), reason="/tmp must be available")
    def test_build_extensions(self):
        """Test building from the extensions config file example."""
        test_config_file = str(Path("examples/extension_example.yaml").absolute())

        result = self.cli.invoke(
            app,
            [
                "build",
                test_config_file,
            ],
        )
        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            "Created new CSR at /tmp/my_extension_autocsr.csr\n",
            "Should print success to user",
        )

    @pytest.mark.skipif(not Path("/tmp").exists(), reason="/tmp must be available")
    def test_build_jinja(self):
        """Test building from the jinja config file example."""
        test_config_file = str(Path("examples/quick_csr.jinja2").absolute())
        os.environ["NAME"] = "Max"

        result = self.cli.invoke(
            app,
            [
                "build",
                test_config_file,
            ],
        )
        self.assertEqual(
            result.exit_code,
            0,
            "Should successfully create a Certificate Signing Request",
        )
        self.assertEqual(
            result.output,
            "Created new CSR at /tmp/Maxs_first_autocsr.csr\n",
            "Should print success to user",
        )
