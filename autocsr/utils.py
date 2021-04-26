"""Utilities for common usage."""

import json
import os
from typing import Generator, List

import yaml
from google.protobuf import json_format
from jinja2 import Template

from autocsr.protos.csr_pb2 import CertificateSigningRequest

CsrList = Generator[CertificateSigningRequest, None, None]


def _load_csr(csr: dict) -> CertificateSigningRequest:
    """Load a CSR from a dictionary."""
    return json_format.Parse(json.dumps(csr), CertificateSigningRequest())


def _load_csrs_from_yaml(config_file: str) -> CsrList:
    """Load a CSR from a YAML file."""
    with open(config_file, "r") as config:
        config_csrs = yaml.safe_load(config.read())

        for csr in config_csrs.values():
            yield _load_csr(csr)


def _load_csrs_from_jinja(config_file: str) -> CsrList:
    """Load a CSR from a Jinja template."""
    with open(config_file, "r") as config:
        config_template = Template(config.read())
        config_csrs = yaml.safe_load(config_template.render(**os.environ))

        for csr in config_csrs.values():
            yield _load_csr(csr)


def load_csrs_from_file(config_file: str) -> List[CertificateSigningRequest]:
    """
    Load all CSRs from a file.

    :param str config_file: A configuration file containing CSR information.
    :return: A list of Certificate Signing Request Objects.
    :rtype: List[CertificateSigningRequest]
    """
    if config_file.endswith(".yaml"):
        return _load_csrs_from_yaml(config_file)

    if config_file.endswith(".jinja2"):
        return _load_csrs_from_jinja(config_file)

    raise TypeError(f"Config file type {config_file} is not supported")
