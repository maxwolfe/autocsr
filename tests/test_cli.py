"""
Tests for the autocsr command line interface
"""

from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest import TestCase

import yaml
from typer.testing import CliRunner

from autocsr.cli import app


class TestCli(TestCase):
    """
    Test command line interfaces
    """

    config = {
        0: {
            "subject": {
                "common_name": "Test CSR",
            },
            "key_path": str(Path("tests/fixtures/test.key").absolute()),
            "output_path": NamedTemporaryFile().name,
        },
    }

    def setUp(self):
        self.cli = CliRunner()
        self.config_file = NamedTemporaryFile().name

        with open(self.config_file, "w") as config:
            config.write(yaml.dump(self.config))

    def test_create(self):
        """
        Test the autocsr create command
        """

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
