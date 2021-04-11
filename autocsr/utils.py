"""
Utilities for common usage
"""

import json
from typing import Generator

import yaml
from google.protobuf import json_format

from autocsr.protos.csr_pb2 import CertificateSigningRequest

CsrList = Generator[CertificateSigningRequest, None, None]


def load_csr(csr: dict) -> CertificateSigningRequest:
    """
    Load a CSR from a dictionary
    """

    return json_format.Parse(json.dumps(csr), CertificateSigningRequest())


def load_csrs_from_file(config_file: str) -> CsrList:
    """
    Load all CSRs from a file
    """

    with open(config_file, "r") as config:
        config_csrs = yaml.safe_load(config.read())

        for csr in config_csrs.values():
            yield load_csr(csr)
