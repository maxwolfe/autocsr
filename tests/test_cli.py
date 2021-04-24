"""Tests for the autocsr command line interface."""

from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest import TestCase

import yaml
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

    def test_from_config(self):
        """Test creating CSRs from config files."""
        result = self.cli.invoke(
            app,
            [self.config_file],
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

    def test_from_common_name(self):
        """Test creating CSRs from a common name."""
        test_common_name = self.config[0]["subject"]["common_name"]
        test_key_path = NamedTemporaryFile().name
        test_output_path = self.config[0]["output_path"]

        result = self.cli.invoke(
            app,
            [
                "--create",
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
